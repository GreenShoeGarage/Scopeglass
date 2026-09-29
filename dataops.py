"""Validated archive restore and reversible-by-backup data maintenance."""
from contextlib import closing
import base64
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from searching import parse_query, SORTS
from monitoring import Conflict

TABLES=('scans','observations','checks','baselines','assets','saved_views','schedules','changes')
SECRET=secrets.token_bytes(32)
MAX_ARCHIVE=16*1024*1024


def init_schema(c):
    c.execute('CREATE TABLE IF NOT EXISTS app_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
    c.execute('INSERT OR IGNORE INTO app_meta VALUES(?,?)',('epoch',secrets.token_hex(16)))


def epoch(c):return c.execute("SELECT value FROM app_meta WHERE key='epoch'").fetchone()[0]
def timestamp():return dt.datetime.now(dt.timezone.utc).isoformat()
def encode(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
def digest(value):return hashlib.sha256(encode(value).encode()).hexdigest()
def snapshot_hash(data):return digest({key:data[key] for key in TABLES})


def integer(value,label,lo=0,hi=2**53-1):
    if type(value) is not int or not lo<=value<=hi:raise ValueError(f'{label}: expected an integer between {lo} and {hi}.')
    return value


def text(value,label,limit=4000):
    if not isinstance(value,str) or len(value)>limit or '\x00' in value:raise ValueError(f'{label}: invalid text or exceeds {limit} characters.')
    return value


def moment(value,label,nullable=False):
    if nullable and value is None:return None
    text(value,label,64)
    try:
        parsed=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
        if parsed.tzinfo is None:raise ValueError()
    except (ValueError,TypeError):raise ValueError(f'{label}: use an ISO timestamp with timezone.')
    return parsed.astimezone(dt.timezone.utc).isoformat()


def ip(value):
    if not isinstance(value,str):raise ValueError('Host must be IPv4 text.')
    return str(ipaddress.IPv4Address(value))


def array(value,label,limit,encoded=False):
    if encoded and isinstance(value,str):value=json.loads(value)
    if not isinstance(value,list) or len(value)>limit:raise ValueError(f'{label}: expected a list with at most {limit} entries.')
    return value


def ports(value,limit=128,empty=False):
    result=[integer(p,'Port',1,65535) for p in array(value,'Ports',limit,True)]
    if len(result)!=len(set(result)) or (not result and not empty):raise ValueError('Ports must be nonempty and unique.')
    return sorted(result)


def metadata(value):
    if isinstance(value,str):value=json.loads(value)
    if not isinstance(value,dict) or len(encode(value))>32000:raise ValueError('Metadata must be an object of at most 32,000 characters.')
    def check(item,depth=0):
        if depth>12:raise ValueError('Metadata nesting exceeds 12 levels.')
        if isinstance(item,dict):
            for k,v in item.items():text(k,'Metadata key',100);check(v,depth+1)
        elif isinstance(item,list):
            if len(item)>128:raise ValueError('Metadata list is too long.')
            for v in item:check(v,depth+1)
        elif item is not None and type(item) not in (str,int,float,bool):raise ValueError('Unsupported metadata value.')
    check(value)
    for key in ('protocol','identification','probe_note'):
        if key in value:text(value[key],'Metadata '+key,1000)
    if value.get('identification','port_hint') not in ('port_hint','verified'):raise ValueError('Invalid identification label.')
    if value.get('identification')=='verified' and not value.get('protocol'):raise ValueError('Verified metadata requires a protocol.')
    if 'evidence' in value:
        for v in array(value['evidence'],'Evidence',64):text(v,'Evidence',4000)
    for key in ('http','rtsp','tls','device'):
        if key in value and not isinstance(value[key],dict):raise ValueError('Metadata '+key+' must be an object.')
    for section in ('http','rtsp','tls'):
        for key,item in value.get(section,{}).items():
            if key=='status' and section!='tls':integer(item,'Protocol status',100,599)
            elif key!='names':text(item,section+' '+key,4000)
    if 'device' in value:
        for key in ('kind','label','confidence','evidence'):
            if key in value['device']:text(value['device'][key],'Device '+key,4000)
    tls=value.get('tls',{})
    if 'names' in tls:
        for v in array(tls['names'],'Certificate names',128):text(v,'Certificate name',1000)
    return value


def validate_archive(source,presets):
    if not isinstance(source,dict) or source.get('schema')!='scopeglass.export.v1':raise ValueError('Choose a Scopeglass JSON export (scopeglass.export.v1).')
    if len(encode(source).encode())>MAX_ARCHIVE:raise ValueError('Archive exceeds the 16 MiB restore limit. Use a SQLite backup for larger inventories.')
    version=text(source.get('version',''),'Version',40)
    if not version.startswith(('0.3.','0.4.','0.5.','0.6.','0.7.','0.8.','0.9.')) and version!='1.0.0-rc.1':raise ValueError('Supported JSON export versions: v0.3 through v0.9 and v1.0.0-rc.1. Use a SQLite backup for older or newer versions.')
    moment(source.get('exported'),'Export timestamp')
    data={};warnings=[]
    for table in TABLES:
        if table not in source and table in ('scans','observations','checks','baselines'):raise ValueError('Missing archive table: '+table)
        data[table]=array(source.get(table,[]),table,200000)
        if any(not isinstance(r,dict) for r in data[table]):raise ValueError(table+' records must be objects.')
    if sum(len(v) for v in data.values())>250000:raise ValueError('Archive exceeds 250,000 records. Use a SQLite backup.')
    scans={};normalized={key:[] for key in TABLES}
    def ident(row,table,seen):
        value=integer(row.get('id'),table+' ID',1)
        if value in seen:raise ValueError('Duplicate '+table+' ID.')
        seen.add(value);return value
    seen=set()
    for row in data['scans']:
        sid=ident(row,'scan',seen);hosts=[ip(v) for v in array(row.get('targets'),'Targets',256,True)];ps=ports(row.get('ports'))
        if not hosts or len(hosts)!=len(set(hosts)):raise ValueError('Scan targets must be nonempty and unique.')
        status=row.get('status')
        if status not in ('running','complete','failed','cancelled','interrupted'):raise ValueError('Invalid scan status.')
        total=integer(row.get('total'),'Scan total',1,32768);checked=integer(row.get('checked'),'Checked count',0,total)
        if total!=len(hosts)*len(ps) or (status=='complete' and checked!=total):raise ValueError('Scan coverage is inconsistent.')
        preset=row.get('preset','custom')
        if preset not in ('custom',*presets):raise ValueError('Unknown scan preset.')
        record=dict(id=sid,started=moment(row.get('started'),'Scan started'),finished=moment(row.get('finished'),'Scan finished',True),status=status,targets=encode(hosts),ports=encode(ps),checked=checked,total=total,preset=preset,error=text(row.get('error',''),'Scan error'),parent_scan=row.get('parent_scan'),schedule_id=row.get('schedule_id'),comparison_scan=row.get('comparison_scan'),comparison_status=text(row.get('comparison_status',''),'Comparison status',200))
        if status=='running':record.update(status='interrupted',finished=timestamp(),error='Archive captured this scan while running. Partial observations retained.',comparison_status='skipped: restored partial scan');warnings.append('Running scans become interrupted; no scan resumes automatically.')
        scans[sid]=record;normalized['scans'].append(record)
    for row in normalized['scans']:
        for key in ('parent_scan','comparison_scan'):
            if row[key] is not None:
                integer(row[key],key,1)
                if row[key] not in scans or row[key]>=row['id']:raise ValueError('Invalid scan reference: '+key)
    coverage={sid:(set(json.loads(r['targets'])),set(json.loads(r['ports']))) for sid,r in scans.items()}
    def pair(row):
        sid=integer(row.get('scan_id'),'Scan reference',1);host=ip(row.get('host'));port=integer(row.get('port'),'Port',1,65535)
        if sid not in coverage or host not in coverage[sid][0] or port not in coverage[sid][1]:raise ValueError('An observation/check falls outside its scan scope.')
        return sid,host,port
    for sid,row in scans.items():
        parent=row['parent_scan'];previous=row['comparison_scan']
        if parent is not None and (not coverage[sid][0]<=coverage[parent][0] or not coverage[sid][1]<=coverage[parent][1]):raise ValueError('Focused scan falls outside its parent scope.')
        if previous is not None and (coverage[sid]!=coverage[previous] or scans[previous]['status']!='complete'):raise ValueError('Invalid comparison scope or incomplete reference scan.')
    checks={};counts={sid:0 for sid in scans}
    for row in data['checks']:
        key=pair(row);outcome=row.get('outcome')
        if key in checks or outcome not in ('open','refused','timeout','unreachable'):raise ValueError('Duplicate check or invalid outcome.')
        checks[key]=outcome;counts[key[0]]+=1;normalized['checks'].append(dict(scan_id=key[0],host=key[1],port=key[2],outcome=outcome))
    for sid,count in counts.items():
        # Migrated v0.2 scans may have inferred counts but no historical checks.
        if count and count!=scans[sid]['checked']:raise ValueError('Recorded checks do not match the scan checked count.')
        if not count and scans[sid]['checked']:warnings.append('Some legacy scans have inferred coverage without per-check outcomes.')
    seen=set();pairs=set();observed={}
    for row in data['observations']:
        oid=ident(row,'observation',seen);key=pair(row)
        if key in pairs or (counts[key[0]] and checks.get(key)!='open'):raise ValueError('Duplicate observation or missing open check.')
        pairs.add(key);normalized['observations'].append(dict(id=oid,scan_id=key[0],host=key[1],port=key[2],service=text(row.get('service'),'Service',100),banner=text(row.get('banner'),'Banner',2000),observed=moment(row.get('observed'),'Observed timestamp'),metadata=encode(metadata(row.get('metadata',{})))))
        record=normalized['observations'][-1];observed[key]={k:(json.loads(record[k]) if k=='metadata' else record[k]) for k in ('observed','service','banner','metadata')}
    if any(v=='open' and key not in pairs for key,v in checks.items()):raise ValueError('An open check is missing its observation.')
    seen=set()
    for row in data['baselines']:
        bid=ident(row,'baseline',seen);sid=integer(row.get('scan_id'),'Baseline scan',1)
        if sid not in scans or scans[sid]['status']!='complete':raise ValueError('Baseline requires a completed scan.')
        normalized['baselines'].append(dict(id=bid,created=moment(row.get('created'),'Baseline created'),note=text(row.get('note',''),'Baseline note',120),scan_id=sid))
    seen=set()
    for row in data['assets']:
        host=ip(row.get('host'))
        if host in seen:raise ValueError('Duplicate device annotation.')
        seen.add(host);tags=[text(v,'Tag',32) for v in array(row.get('tags'),'Tags',12,True)]
        normalized['assets'].append(dict(host=host,name=text(row.get('name'),'Device name',120),notes=text(row.get('notes'),'Device notes',4000),tags=encode(tags),expected_ports=encode(ports(row.get('expected_ports'),1024,True)),revision=integer(row.get('revision'),'Device revision',1),updated=moment(row.get('updated'),'Device updated')))
    seen=set();names=set()
    for row in data['saved_views']:
        vid=ident(row,'view',seen);name=text(row.get('name'),'View name',80);settings=row.get('settings')
        if not name.strip() or name in names or not isinstance(settings,dict):raise ValueError('Invalid or duplicate saved view.')
        names.add(name);parse_query(settings.get('q'));selection=str(settings.get('scan'))
        if settings.get('category') not in ('all',*presets) or settings.get('view') not in ('devices','services') or settings.get('sort') not in SORTS:raise ValueError('Invalid saved view settings.')
        if selection!='latest' and (not selection.isdecimal() or int(selection) not in scans):raise ValueError('Saved view references a missing scan.')
        normalized['saved_views'].append(dict(id=vid,name=name,settings=encode({k:settings[k] for k in ('q','category','sort','view','scan')}),revision=integer(row.get('revision'),'View revision',1),updated=moment(row.get('updated'),'View updated')))
    seen=set();names=set()
    for row in data['schedules']:
        sid=ident(row,'schedule',seen);source_id=integer(row.get('source_scan'),'Schedule source',1)
        if source_id not in scans or scans[source_id]['status']!='complete':raise ValueError('Schedule source requires a completed scan.')
        hosts=[ip(v) for v in array(row.get('targets'),'Scheduled targets',256,True)];ps=ports(row.get('ports'));source_scope=coverage[source_id]
        if set(hosts)!=source_scope[0] or len(hosts)!=len(set(hosts)) or set(ps)!=source_scope[1]:raise ValueError('Schedule scope differs from its source scan.')
        name=text(row.get('name'),'Schedule name',80);deleted=integer(row.get('deleted',0),'Deleted flag',0,1);enabled=integer(row.get('enabled'),'Enabled flag',0,1)
        if not name.strip() or (not deleted and name in names):raise ValueError('Duplicate or empty schedule name.')
        if not deleted:names.add(name)
        if len(names)>50:raise ValueError('More than 50 active schedules.')
        last=row.get('last_scan')
        if last is not None and (type(last) is not int or last not in scans):raise ValueError('Schedule last scan is missing.')
        if row.get('preset') not in ('custom',*presets):raise ValueError('Invalid schedule preset.')
        normalized['schedules'].append(dict(id=sid,name=name,source_scan=source_id,targets=encode(hosts),ports=encode(ps),preset=row['preset'],interval_minutes=integer(row.get('interval_minutes'),'Repeat minutes',15,10080),enabled=0,next_run=moment(row.get('next_run'),'Next run'),last_scan=last,last_error='Restored from JSON; review scope and resume explicitly.' if not deleted else text(row.get('last_error',''),'Schedule error'),deleted=deleted,revision=integer(row.get('revision'),'Schedule revision',1)+1,updated=timestamp()))
    schedules={r['id']:r for r in normalized['schedules']}
    if schedules:warnings.append('All restored schedules are paused. Review their scopes before resuming.')
    for row in normalized['scans']:
        if row['schedule_id'] is not None and (type(row['schedule_id']) is not int or row['schedule_id'] not in schedules):raise ValueError('Scan references a missing schedule.')
        if row['schedule_id'] is not None and coverage[row['id']]!=coverage[schedules[row['schedule_id']]['source_scan']]:raise ValueError('Scheduled scan scope differs from its source.')
    for row in schedules.values():
        if row['last_scan'] is not None and scans[row['last_scan']]['schedule_id']!=row['id']:raise ValueError('Schedule last scan belongs to another schedule.')
    seen=set();unique=set()
    for row in data['changes']:
        cid=ident(row,'change',seen);sid=integer(row.get('scan_id'),'Change scan',1);previous=integer(row.get('previous_scan'),'Previous scan',1);schedule=integer(row.get('schedule_id'),'Change schedule',1);host=ip(row.get('host'));port=integer(row.get('port'),'Change port',1,65535);kind=row.get('kind')
        if schedule not in schedules or sid not in scans or previous not in scans or sid==previous or scans[sid]['status']!='complete' or scans[previous]['status']!='complete' or coverage[sid]!=coverage[previous] or scans[sid]['schedule_id']!=schedule:raise ValueError('Invalid change scan/schedule references.')
        if host not in coverage[sid][0] or port not in coverage[sid][1] or kind not in ('new','not_observed','protocol_changed','certificate_changed'):raise ValueError('Invalid change kind or scope.')
        key=(sid,host,port,kind)
        if key in unique:raise ValueError('Duplicate change.')
        unique.add(key);ev=row.get('evidence')
        if not isinstance(ev,dict) or ev.get('outcome') not in ('open','refused','timeout','unreachable','unknown'):raise ValueError('Invalid change evidence.')
        clean={'outcome':ev['outcome']}
        for side in ('before','after'):
            value=ev.get(side)
            if value is None:clean[side]=None;continue
            if not isinstance(value,dict):raise ValueError('Change snapshot must be an object.')
            clean[side]=dict(observed=moment(value.get('observed'),'Change observation'),service=text(value.get('service'),'Change service',100),banner=text(value.get('banner'),'Change banner',2000),metadata=metadata(value.get('metadata',{})))
        if (kind=='new' and (clean['before'] is not None or clean['after'] is None)) or (kind=='not_observed' and (clean['before'] is None or clean['after'] is not None)) or (kind in ('protocol_changed','certificate_changed') and (clean['before'] is None or clean['after'] is None)):raise ValueError('Change evidence does not match its kind.')
        if clean['before']!=observed.get((previous,host,port)) or clean['after']!=observed.get((sid,host,port)) or clean['outcome']!=checks.get((sid,host,port),'unknown'):raise ValueError('Change evidence differs from the referenced observations or check outcome.')
        normalized['changes'].append(dict(id=cid,schedule_id=schedule,schedule_name=text(row.get('schedule_name'),'Change schedule name',80),scan_id=sid,previous_scan=previous,created=moment(row.get('created'),'Change created'),host=host,port=port,kind=kind,evidence=encode(clean),reviewed=moment(row.get('reviewed'),'Reviewed timestamp',True)))
    return normalized,sorted(set(warnings))


def cleanup_plan(snapshot,days):
    integer(days,'Retention days',1,3650)
    cutoff=dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=days)
    scans={s['id']:s for s in snapshot['scans']};keep=set()
    if scans:keep.add(max(scans))
    keep.update(b['scan_id'] for b in snapshot['baselines'])
    for view in snapshot['saved_views']:
        selection=view['settings']['scan']
        if selection!='latest':keep.add(int(selection))
    for schedule in snapshot['schedules']:
        keep.add(schedule['source_scan'])
        if schedule['last_scan']:keep.add(schedule['last_scan'])
    for change in snapshot['changes']:keep.update((change['scan_id'],change['previous_scan']))
    eligible=set()
    for sid,scan in scans.items():
        try:old=dt.datetime.fromisoformat(scan['started'])<cutoff
        except (ValueError,TypeError):old=False
        if old and scan['status']!='running':eligible.add(sid)
        else:keep.add(sid)
    # Preserve the complete reference chain for retained focused/scheduled scans.
    pending=list(keep)
    while pending:
        scan=scans.get(pending.pop(),{})
        for key in ('parent_scan','comparison_scan'):
            ref=scan.get(key)
            if ref is not None and ref not in keep:keep.add(ref);pending.append(ref)
    remove=sorted(eligible-keep)
    return remove,len(eligible&keep)


def sign(action,options,current):
    payload=base64.urlsafe_b64encode(encode({'action':action,'options':digest(options),'current':current,'expires':int(time.time())+600}).encode()).decode()
    return payload+'.'+hmac.new(SECRET,payload.encode(),hashlib.sha256).hexdigest()


def verify(token,action,options,current):
    try:
        payload,signature=token.split('.')
        if not hmac.compare_digest(signature,hmac.new(SECRET,payload.encode(),hashlib.sha256).hexdigest()):raise ValueError()
        info=json.loads(base64.urlsafe_b64decode(payload))
        if info['action']!=action or info['options']!=digest(options) or info['current']!=current or info['expires']<time.time():raise ValueError()
    except (ValueError,TypeError,KeyError,AttributeError):raise Conflict('The data or preview changed, or the preview expired. Preview this operation again.')


def safety_backup(database):
    folder=Path(database).resolve().parent/'backups';folder.mkdir(mode=0o700,exist_ok=True)
    name='scopeglass-before-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+secrets.token_hex(4)+'.sqlite3'
    target=folder/name
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
    try:
        with closing(sqlite3.connect(database)) as source,closing(sqlite3.connect(target)) as dest:
            source.backup(dest)
            if dest.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise OSError('Backup integrity check failed.')
        with target.open('rb') as stream:os.fsync(stream.fileno())
    except Exception:
        target.unlink(missing_ok=True);raise
    return str(target)


def replace_data(c,data):
    for table in reversed(TABLES):c.execute(f'DELETE FROM {table}')
    for table in TABLES:
        for row in data[table]:
            fields=list(row);c.execute(f'INSERT INTO {table}({",".join(fields)}) VALUES({",".join("?" for _ in fields)})',tuple(row[k] for k in fields))
    c.execute("UPDATE app_meta SET value=? WHERE key='epoch'",(secrets.token_hex(16),))
