"""Durable recurring assessment settings and evidence-based change records."""
import datetime as dt
import json


class Conflict(ValueError):
    pass


def stamp():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def after(minutes, reference=None):
    current = dt.datetime.fromisoformat(reference) if reference else dt.datetime.now(dt.timezone.utc)
    return (current + dt.timedelta(minutes=minutes)).isoformat()


def init_schema(c):
    c.executescript('''
    CREATE TABLE IF NOT EXISTS schedules(
      id INTEGER PRIMARY KEY, name TEXT NOT NULL, source_scan INTEGER NOT NULL,
      targets TEXT NOT NULL, ports TEXT NOT NULL, preset TEXT NOT NULL,
      interval_minutes INTEGER NOT NULL, enabled INTEGER NOT NULL, next_run TEXT NOT NULL,
      last_scan INTEGER, last_error TEXT NOT NULL DEFAULT '', deleted INTEGER NOT NULL DEFAULT 0,
      revision INTEGER NOT NULL DEFAULT 1, updated TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS changes(
      id INTEGER PRIMARY KEY, schedule_id INTEGER NOT NULL, schedule_name TEXT NOT NULL,
      scan_id INTEGER NOT NULL, previous_scan INTEGER NOT NULL, created TEXT NOT NULL,
      host TEXT NOT NULL, port INTEGER NOT NULL, kind TEXT NOT NULL, evidence TEXT NOT NULL,
      reviewed TEXT, UNIQUE(scan_id,host,port,kind));
    CREATE INDEX IF NOT EXISTS changes_review ON changes(reviewed,id);
    ''')
    columns = {r['name'] for r in c.execute('PRAGMA table_info(scans)')}
    for name, definition in [('schedule_id','INTEGER'),('comparison_scan','INTEGER'),
                             ('comparison_status',"TEXT NOT NULL DEFAULT ''")]:
        if name not in columns:
            c.execute(f'ALTER TABLE scans ADD COLUMN {name} {definition}')


def edit_schedule(c, data, action, validate):
    """Caller owns an immediate transaction and scanner lock."""
    sid = data.get('id')
    if sid is not None and type(sid) is not int:
        raise ValueError('Schedule ID must be an integer.')
    existing = c.execute('SELECT * FROM schedules WHERE id=? AND deleted=0',(sid,)).fetchone() if sid is not None else None
    if sid is not None and (not existing or type(data.get('revision')) is not int or existing['revision'] != data['revision']):
        raise Conflict('This schedule changed or was removed. Refresh schedules before trying again.')
    if action != 'save' and existing is None:
        raise ValueError('Choose a saved schedule.')
    if action in ('pause','resume','delete'):
        if action == 'resume':
            validate({'targets':'\n'.join(json.loads(existing['targets'])), 'ports':','.join(map(str,json.loads(existing['ports'])))})
        enabled = int(action == 'resume')
        c.execute('UPDATE schedules SET enabled=?,deleted=?,next_run=?,last_error=?,revision=revision+1,updated=? WHERE id=?',
                  (enabled,int(action=='delete'),after(existing['interval_minutes']) if enabled else existing['next_run'],
                   '' if enabled else existing['last_error'],stamp(),sid))
        return sid
    if action != 'save':
        raise ValueError('Unknown schedule action.')
    name = data.get('name','')
    interval = data.get('interval_minutes')
    if not isinstance(name,str) or not name.strip() or len(name.strip())>80:
        raise ValueError('Use a schedule name of 1–80 characters.')
    if type(interval) is not int or not 15<=interval<=10080:
        raise ValueError('Repeat interval must be 15–10,080 whole minutes.')
    name = name.strip()
    if c.execute('SELECT id FROM schedules WHERE name=? AND deleted=0 AND id!=?',(name,sid or -1)).fetchone():
        raise Conflict('That schedule name already exists. Edit it or choose a different name.')
    if existing:
        due = after(interval) if interval != existing['interval_minutes'] else existing['next_run']
        c.execute('UPDATE schedules SET name=?,interval_minutes=?,next_run=?,revision=revision+1,updated=? WHERE id=?',
                  (name,interval,due,stamp(),sid))
    else:
        if c.execute('SELECT count(*) FROM schedules WHERE deleted=0').fetchone()[0]>=50:
            raise ValueError('At most 50 schedules. Remove an unused schedule first.')
        if type(data.get('scan_id')) is not int:
            raise ValueError('Choose a completed source scan.')
        source = c.execute('SELECT * FROM scans WHERE id=?',(data['scan_id'],)).fetchone()
        if not source or source['status']!='complete':
            raise ValueError('Schedules need a completed source scan.')
        hosts, ports, _ = validate({'targets':'\n'.join(json.loads(source['targets'])), 'ports':','.join(map(str,json.loads(source['ports'])))})
        sid = c.execute('INSERT INTO schedules(name,source_scan,targets,ports,preset,interval_minutes,enabled,next_run,updated) VALUES(?,?,?,?,?,?,1,?,?)',
                        (name,source['id'],json.dumps(hosts),json.dumps(ports),source['preset'],interval,after(interval),stamp())).lastrowid
    return sid


def evidence(row):
    if not row:
        return None
    meta = json.loads(row['metadata'])
    return {'observed':row['observed'],'service':row['service'],'banner':row['banner'],'metadata':meta}


def record_changes(c, scan_id):
    """Commit with scan completion; never infer absence from a partial scan."""
    current = c.execute('SELECT * FROM scans WHERE id=?',(scan_id,)).fetchone()
    if current['schedule_id'] is None:
        return
    previous = c.execute('SELECT * FROM scans WHERE id=?',(current['comparison_scan'],)).fetchone()
    comparable = (current['status']=='complete' and previous and previous['status']=='complete'
                  and set(json.loads(current['targets']))==set(json.loads(previous['targets']))
                  and set(json.loads(current['ports']))==set(json.loads(previous['ports'])))
    if not comparable:
        c.execute("UPDATE scans SET comparison_status='skipped: incomplete or different scope' WHERE id=?",(scan_id,))
        return
    schedule = c.execute('SELECT name FROM schedules WHERE id=?',(current['schedule_id'],)).fetchone()
    old = {(r['host'],r['port']):r for r in c.execute('SELECT * FROM observations WHERE scan_id=?',(previous['id'],))}
    new = {(r['host'],r['port']):r for r in c.execute('SELECT * FROM observations WHERE scan_id=?',(scan_id,))}
    checks = {(r['host'],r['port']):r['outcome'] for r in c.execute('SELECT * FROM checks WHERE scan_id=?',(scan_id,))}
    count = 0
    for host,port in sorted(old.keys()|new.keys()):
        before, latest = evidence(old.get((host,port))), evidence(new.get((host,port)))
        kinds = []
        if before is None: kinds.append('new')
        elif latest is None: kinds.append('not_observed')
        else:
            a,b = before['metadata'],latest['metadata']
            if a.get('identification')=='verified' and b.get('identification')=='verified' and a.get('protocol')!=b.get('protocol'):
                kinds.append('protocol_changed')
            a,b = a.get('tls',{}).get('sha256'),b.get('tls',{}).get('sha256')
            if a and b and a!=b: kinds.append('certificate_changed')
        for kind in kinds:
            c.execute('INSERT OR IGNORE INTO changes(schedule_id,schedule_name,scan_id,previous_scan,created,host,port,kind,evidence) VALUES(?,?,?,?,?,?,?,?,?)',
                      (current['schedule_id'],schedule['name'],scan_id,previous['id'],stamp(),host,port,kind,
                       json.dumps({'before':before,'after':latest,'outcome':checks.get((host,port),'unknown')})))
            count += 1
    c.execute('UPDATE scans SET comparison_status=? WHERE id=?',('compared: '+str(count)+' changes',scan_id))
