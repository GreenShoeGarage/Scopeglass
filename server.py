#!/usr/bin/env python3
"""Scopeglass — self-hosted network observations. Python standard library only."""
import argparse
import access
import deployment
import os
import signal
import concurrent.futures as futures
from contextlib import contextmanager
import datetime as dt
import ipaddress
import hmac
import json
from pathlib import Path
import platform
import re
import socket
import sqlite3
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import monitoring
import dataops
from protocols import inspect_service
from searching import parse_query, matches, sort_items, observed_age, SORTS

ROOT = Path(__file__).resolve().parent
VERSION = '1.0.0-rc.1'
MAX_HOSTS, MAX_PORTS, MAX_CONCURRENCY = 256, 128, 16
PRESETS = {
    'overview': {'name': 'Network overview', 'ports': [21,22,23,53,80,81,139,443,445,554,1883,2049,2323,3389,5900,5901,8000,8001,8080,8081,8443,8554,8899,9000,9090]},
    'cameras': {'name': 'Possible cameras', 'ports': [80,81,443,554,8000,8001,8080,8081,8554,8899,9000]},
    'telnet': {'name': 'Possible Telnet', 'ports': [23,2323]},
    'remote': {'name': 'Remote access', 'ports': [21,22,23,2323,3389,5900,5901]},
    'web': {'name': 'Web interfaces', 'ports': [80,81,443,8000,8001,8080,8081,8443,9000,9090]},
    'file': {'name': 'File sharing', 'ports': [21,139,445,2049]},
}
CAMERA_WORDS = ('camera','webcam','ipcam','ip camera','onvif','dvr','nvr','hikvision','dahua','axis communications')
DB = None
CONFIG = None
LOCK = threading.RLock()
CANCEL = threading.Event()
SCAN_THREAD = None
STATE = {'running': False, 'completed': 0, 'total': 0, 'error': '', 'scan_id': None, 'cancelling': False}


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


@contextmanager
def db():
    connection = sqlite3.connect(DB, timeout=20)
    connection.row_factory = sqlite3.Row
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def init_db():
    with db() as c:
        deployment.check_schema(c)
        c.execute('PRAGMA journal_mode=WAL')
        c.executescript('''
        CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, started TEXT NOT NULL,
          finished TEXT, status TEXT NOT NULL, targets TEXT NOT NULL, ports TEXT NOT NULL, error TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS observations(id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL,
          host TEXT NOT NULL, port INTEGER NOT NULL, service TEXT NOT NULL, banner TEXT NOT NULL,
          observed TEXT NOT NULL, FOREIGN KEY(scan_id) REFERENCES scans(id));
        CREATE INDEX IF NOT EXISTS observations_host ON observations(host,port,scan_id);
        CREATE TABLE IF NOT EXISTS baselines(id INTEGER PRIMARY KEY, created TEXT NOT NULL,
          note TEXT NOT NULL, scan_id INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS checks(scan_id INTEGER NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
          outcome TEXT NOT NULL, PRIMARY KEY(scan_id,host,port));
        ''')
        columns = {r['name'] for r in c.execute('PRAGMA table_info(scans)')}
        for name, definition in [('checked','INTEGER NOT NULL DEFAULT 0'), ('total','INTEGER NOT NULL DEFAULT 0'),
                                 ('preset',"TEXT NOT NULL DEFAULT 'custom'"), ('parent_scan','INTEGER')]:
            if name not in columns:
                c.execute(f'ALTER TABLE scans ADD COLUMN {name} {definition}')
        for row in c.execute('SELECT * FROM scans WHERE total=0').fetchall():
            total = len(json.loads(row['targets'])) * len(json.loads(row['ports']))
            c.execute('UPDATE scans SET total=?,checked=? WHERE id=?',
                      (total, total if row['status']=='complete' else row['checked'], row['id']))
        c.execute("UPDATE scans SET status='interrupted',finished=?,error=? WHERE status='running'",
                  (now(), 'Server stopped during this scan. Saved observations were retained; start a new scan to finish assessing this scope.'))
        observation_columns = {r['name'] for r in c.execute('PRAGMA table_info(observations)')}
        if 'metadata' not in observation_columns:
            c.execute("ALTER TABLE observations ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}'")
        c.execute("CREATE TABLE IF NOT EXISTS assets(host TEXT PRIMARY KEY,name TEXT NOT NULL,tags TEXT NOT NULL,notes TEXT NOT NULL,expected_ports TEXT NOT NULL,revision INTEGER NOT NULL,updated TEXT NOT NULL)")
        c.execute("CREATE TABLE IF NOT EXISTS saved_views(id INTEGER PRIMARY KEY,name TEXT NOT NULL UNIQUE,settings TEXT NOT NULL,revision INTEGER NOT NULL,updated TEXT NOT NULL)")
        monitoring.init_schema(c)
        c.execute("UPDATE scans SET comparison_status='skipped: interrupted scan' WHERE status='interrupted' AND schedule_id IS NOT NULL AND comparison_status=''")
        dataops.init_schema(c)
        access.init_schema(c)
        c.execute(f'PRAGMA user_version={deployment.SCHEMA_VERSION}')


def rows(query, params=()):
    with db() as c:
        return [dict(r) for r in c.execute(query, params)]


def current_epoch():
    with db() as c:return dataops.epoch(c)


def export_snapshot(connection=None):
    if connection is None:
        with db() as c:
            c.execute('BEGIN')
            return export_snapshot(c)
    c=connection
    result = {'schema':'scopeglass.export.v1','version':VERSION,'exported':now()}
    for table, order in [('scans','id'),('observations','id'),('baselines','id'),
                         ('schedules','id'),('changes','id'),('checks','scan_id,host,port'),
                         ('assets','host'),('saved_views','id')]:
        result[table] = [dict(row) for row in c.execute(f'SELECT * FROM {table} ORDER BY {order}')]
    for row in result['changes']: row['evidence'] = json.loads(row['evidence'])
    for row in result['assets']:
        row['tags'] = json.loads(row['tags']); row['expected_ports'] = json.loads(row['expected_ports'])
    for row in result['saved_views']: row['settings'] = json.loads(row['settings'])
    return result


def latest():
    result = rows('SELECT * FROM scans ORDER BY id DESC LIMIT 1')
    return result[0] if result else None


def addresses(text):
    if not isinstance(text, str):
        raise ValueError('Targets must be IPv4 addresses or CIDRs.')
    allowed = [ipaddress.ip_network(x, strict=False) for x in CONFIG['allowed_cidrs']]
    result = set()
    for raw in text.replace(',', '\n').splitlines():
        if not raw.strip():
            continue
        network = ipaddress.ip_network(raw.strip(), strict=False)
        if network.version != 4:
            raise ValueError('This release accepts IPv4 addresses and CIDRs only.')
        size = network.num_addresses if network.prefixlen >= 31 else network.num_addresses-2
        if size > MAX_HOSTS:
            raise ValueError(f'This range contains {size:,} hosts. Choose a smaller range (usually /24 or narrower); limit {MAX_HOSTS}.')
        for ip in network.hosts():
            if not any(ip in scope for scope in allowed):
                raise ValueError(f'{ip} is outside allowed_cidrs in config.json. Update that file and restart the server, or choose an allowed network.')
            result.add(str(ip))
            if len(result) > MAX_HOSTS:
                raise ValueError(f'At most {MAX_HOSTS} distinct hosts per scan.')
    if not result:
        raise ValueError('Choose a network or enter an IPv4 address or CIDR.')
    return sorted(result, key=lambda value: int(ipaddress.ip_address(value)))


def ports_from(text):
    if not isinstance(text, str):
        raise ValueError('Enter TCP ports as a comma-separated list.')
    result = set()
    for token in text.replace(' ', '').split(','):
        if not token:
            continue
        bounds = token.split('-', 1)
        lo, hi = int(bounds[0]), int(bounds[-1])
        if not 1 <= lo <= hi <= 65535:
            raise ValueError('Ports must be between 1 and 65535.')
        if hi-lo+1 > MAX_PORTS:
            raise ValueError(f'At most {MAX_PORTS} ports per scan.')
        result.update(range(lo, hi+1))
        if len(result) > MAX_PORTS:
            raise ValueError(f'At most {MAX_PORTS} ports per scan.')
    if not result:
        raise ValueError('Enter at least one TCP port.')
    return sorted(result)


def plan_scan(data):
    hosts = addresses(data.get('targets', ''))
    preset = data.get('preset', 'custom')
    if preset != 'custom' and preset not in PRESETS:
        raise ValueError('Unknown assessment preset.')
    ports = PRESETS[preset]['ports'] if preset != 'custom' else ports_from(data.get('ports', ''))
    return hosts, ports, preset


def local_networks():
    """Read local OS interface metadata; never send discovery packets."""
    found, messages = [], []
    try:
        system = platform.system()
        if system == 'Linux':
            data = json.loads(subprocess.run(['ip','-j','-4','addr','show','up'], capture_output=True,
                                            text=True, check=True, timeout=4).stdout)
            for interface in data:
                for address in interface.get('addr_info', []):
                    if address.get('family') == 'inet':
                        found.append((interface['ifname'], address['local'], address['prefixlen']))
        elif system == 'Windows':
            command = 'Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,IPAddress,PrefixLength | ConvertTo-Json -Compress'
            data = json.loads(subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',command],
                              capture_output=True, text=True, check=True, timeout=4).stdout or '[]')
            for address in ([data] if isinstance(data, dict) else data):
                found.append((address['InterfaceAlias'], address['IPAddress'], address['PrefixLength']))
        elif system == 'Darwin':
            output = subprocess.run(['/sbin/ifconfig'], capture_output=True, text=True, check=True, timeout=4).stdout
            name = ''
            for line in output.splitlines():
                if line and not line[0].isspace():
                    name = line.split(':', 1)[0]
                match = re.search(r'\binet (\d+\.\d+\.\d+\.\d+) netmask (\S+)', line)
                if match:
                    mask = match[2]
                    if mask.startswith('0x'):
                        mask = str(ipaddress.IPv4Address(int(mask, 16)))
                    found.append((name, match[1], ipaddress.IPv4Network('0.0.0.0/'+mask).prefixlen))
        else:
            messages.append('Automatic interface detection is unavailable on this operating system.')
    except (OSError, subprocess.SubprocessError, ValueError, KeyError) as error:
        messages.append('Could not read local interface information. Enter a network manually or choose a configured scope.')
    suggestions, seen = [], set()
    for name, address, prefix in found:
        ip = ipaddress.ip_address(address)
        if ip.is_loopback or ip.is_unspecified:
            continue
        actual = ipaddress.ip_network(f'{address}/{prefix}', strict=False)
        target = ipaddress.ip_network(f'{address}/{max(int(prefix),24)}', strict=False)
        key = (name, str(target))
        if key in seen:
            continue
        seen.add(key)
        try:
            count = len(addresses(str(target)))
            allowed, reason = True, ''
        except ValueError as error:
            count, allowed, reason = None, False, str(error)
        suggestions.append({'interface':name, 'address':address, 'network':str(actual), 'target':str(target),
                            'partial':actual != target, 'allowed':allowed, 'reason':reason, 'hosts':count,
                            'source':'interface'})
    for scope in CONFIG['allowed_cidrs']:
        network = ipaddress.ip_network(scope, strict=False)
        if network.version == 4 and network.prefixlen >= 24 and not network.is_loopback:
            if any(x['target'] == str(network) for x in suggestions):
                continue
            suggestions.append({'interface':'Configured scope', 'address':'', 'network':str(network),
                                'target':str(network), 'partial':False, 'allowed':True, 'reason':'',
                                'hosts':len(addresses(str(network))), 'source':'config'})
    return {'networks':suggestions, 'messages':messages,
            'note':'These interfaces belong to the computer running Scopeglass. VPN and container interfaces may also appear.'}


def metadata_for(row):
    value = row.get('metadata', {})
    if isinstance(value, str):
        try: value = json.loads(value)
        except (ValueError,TypeError): value = {}
    return value if isinstance(value, dict) else {}


def classify(row):
    port = row['port']
    meta = metadata_for(row)
    protocol = meta.get('protocol','unknown')
    unknown = protocol == 'unknown'
    result = []
    def add(category, severity, confidence, evidence):
        result.append(dict(category=category,severity=severity,confidence=confidence,evidence=evidence))
    if protocol == 'telnet' or (unknown and port in (23,2323)):
        add('Possible Telnet','high','high' if protocol=='telnet' else 'low',
            'Telnet option negotiation was observed.' if protocol=='telnet' else f'Port {port} accepted a connection; Telnet is not verified.')
    if meta.get('device',{}).get('kind')=='camera':
        add('Possible camera interface','medium','medium',meta['device']['evidence'])
    elif protocol=='rtsp' or (unknown and port in (554,8554)):
        add('Possible camera interface','medium','low','RTSP is verified, but the device could be a media server rather than a camera.' if protocol=='rtsp' else 'A common RTSP port is open; neither protocol nor device type is verified.')
    if protocol in ('ssh','telnet','vnc') or (unknown and port in (22,23,2323,3389,5900,5901)):
        add('Remote access candidate','medium','high' if not unknown else 'low',
            f'{protocol.upper()} response observed.' if not unknown else f'Port {port} is commonly used for remote access; identity is unverified.')
    if protocol=='ftp' or (unknown and port in (21,139,445,2049)):
        add('File sharing or transfer candidate','medium','high' if protocol=='ftp' else 'low',
            'FTP greeting observed.' if protocol=='ftp' else f'Port {port} is commonly used for file sharing; identity is unverified.')
    if protocol in ('http','https') or (unknown and port in PRESETS['web']['ports']):
        add('Web interface candidate','info','high' if not unknown else 'low',
            f"{protocol.upper()} response observed: status {meta.get('http',{}).get('status','unknown')}." if not unknown else f'TCP port {port} accepted a connection; HTTP is not verified.')
    return result


def probe(host, port):
    return inspect_service(host, port)


def run_scan(scan_id, hosts, ports):
    error = ''
    completed = 0
    work = iter((h,p) for h in hosts for p in ports)
    try:
        with futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENCY) as pool:
            pending = {}
            def fill():
                while len(pending) < MAX_CONCURRENCY and not CANCEL.is_set():
                    pair = next(work, None)
                    if pair is None:
                        break
                    pending[pool.submit(probe, *pair)] = pair
            fill()
            while pending:
                ready, _ = futures.wait(pending, return_when=futures.FIRST_COMPLETED)
                for task in ready:
                    host, port = pending.pop(task)
                    result = task.result()
                    completed += 1
                    with db() as c:
                        c.execute('INSERT INTO checks(scan_id,host,port,outcome) VALUES(?,?,?,?)',
                                  (scan_id,host,port,result['outcome']))
                        if result['outcome'] == 'open':
                            c.execute('INSERT INTO observations(scan_id,host,port,service,banner,observed,metadata) VALUES(?,?,?,?,?,?,?)',
                                      (scan_id,host,port,result['service'],result['banner'],now(),json.dumps(result.get('metadata',{}))))
                        c.execute('UPDATE scans SET checked=? WHERE id=?', (completed,scan_id))
                    with LOCK:
                        STATE['completed'] = completed
                fill()
    except Exception as exception:
        error = str(exception)
    status = 'failed' if error else ('complete' if completed == len(hosts)*len(ports) else 'cancelled')
    try:
        with db() as c:
            c.execute('UPDATE scans SET finished=?,status=?,error=? WHERE id=?', (now(),status,error,scan_id))
            monitoring.record_changes(c,scan_id)
    finally:
        with LOCK:
            STATE.update(running=False, error=error, cancelling=False)


def create_scan(c, hosts, ports, preset, parent=None, schedule=None, previous=None):
    return c.execute('INSERT INTO scans(started,status,targets,ports,total,preset,parent_scan,schedule_id,comparison_scan) VALUES(?,?,?,?,?,?,?,?,?)',
                     (now(),'running',json.dumps(hosts),json.dumps(ports),len(hosts)*len(ports),preset,parent,schedule,previous)).lastrowid


def activate_scan(sid, hosts, ports):
    CANCEL.clear()
    STATE.update(running=True,completed=0,total=len(hosts)*len(ports),error='',scan_id=sid,cancelling=False)


def launch_scan(sid, hosts, ports):
    global SCAN_THREAD
    SCAN_THREAD=threading.Thread(target=run_scan,args=(sid,hosts,ports),daemon=True)
    SCAN_THREAD.start()


def schedule_tick(reference=None, requested=None, revision=None):
    """Claim one due job atomically. Busy scanners leave it due; no catch-up queue."""
    reference = reference or now()
    with LOCK:
        if STATE['running']:
            if requested is not None: raise monitoring.Conflict('A scan is already running. Wait for it to finish.')
            return None
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            if requested is None:
                schedule = c.execute('SELECT * FROM schedules WHERE enabled=1 AND deleted=0 AND next_run<=? ORDER BY next_run,id LIMIT 1',(reference,)).fetchone()
                if not schedule: return None
            else:
                if type(requested) is not int: raise ValueError('Choose a saved schedule.')
                schedule = c.execute('SELECT * FROM schedules WHERE id=? AND deleted=0',(requested,)).fetchone()
                if not schedule or type(revision) is not int or schedule['revision']!=revision:
                    raise monitoring.Conflict('This schedule changed or was removed. Refresh schedules before trying again.')
            try:
                hosts,ports,_ = plan_scan({'targets':'\n'.join(json.loads(schedule['targets'])), 'ports':','.join(map(str,json.loads(schedule['ports'])))})
            except ValueError as error:
                c.execute('UPDATE schedules SET enabled=0,last_error=?,revision=revision+1,updated=? WHERE id=?',(str(error),now(),schedule['id']))
                # Commit the visible pause before reporting invalid scope.
                c.commit()
                if requested is not None: raise ValueError(str(error)+' Schedule paused.')
                return None
            previous = c.execute("SELECT id FROM scans WHERE schedule_id=? AND status='complete' ORDER BY id DESC LIMIT 1",(schedule['id'],)).fetchone()
            sid = create_scan(c,hosts,ports,schedule['preset'],schedule=schedule['id'],previous=previous['id'] if previous else schedule['source_scan'])
            c.execute('UPDATE schedules SET next_run=?,last_scan=?,last_error=? WHERE id=?',
                      (monitoring.after(schedule['interval_minutes'],reference),sid,'',schedule['id']))
        activate_scan(sid,hosts,ports)
    launch_scan(sid,hosts,ports)
    return sid


def scheduler_loop(stop):
    while not stop.wait(2):
        try: schedule_tick()
        except Exception as error:
            # Retain the due entry for retry; never silently drop a scheduled assessment.
            print('Scheduler could not start an assessment: '+str(error),flush=True)


def scan_metadata(scan,read=rows):
    if not scan:
        return None
    result = dict(scan)
    result['targets'] = json.loads(result['targets'])
    result['ports'] = json.loads(result['ports'])
    result['outcomes'] = {r['outcome']:r['n'] for r in read('SELECT outcome,count(*) n FROM checks WHERE scan_id=? GROUP BY outcome', (scan['id'],))}
    return result


GUIDANCE = {
    'Possible Telnet': ('A Telnet service may carry login details and session data without encryption. A port hint alone does not confirm Telnet.',
                        'Confirm the service in the device settings. If unused, disable it; if supported, use SSH instead. Rescan after the change.'),
    'Possible camera interface': ('A camera or streaming interface may expose device controls or media. Identification alone does not establish unauthorized access.',
                        'Verify which device owns this address. Review accounts, firmware, and intended network access in its own administration interface, then rescan.'),
    'Remote access candidate': ('Remote access may be expected, but its reachability should match how you administer this device.',
                        'Identify the service and its owner. Restrict access to the intended administration network, disable unused services, then rescan.'),
    'File sharing or transfer candidate': ('File sharing can be normal. Reachability does not show which files or permissions are exposed.',
                        'Review shares, accounts, and guest access on the device. Disable unused sharing or limit who can reach it, then rescan.'),
    'Web interface candidate': ('This may be a management page or an ordinary web application. Reachability does not show whether authentication is effective.',
                        'Identify the application and intended users. Review authentication and HTTPS settings in its administration interface; rescan after changes.'),
}


def asset_for(host,read=rows):
    existing=read('SELECT * FROM assets WHERE host=?',(host,))
    if not existing:
        return {'host':host,'name':'','tags':[],'notes':'','expected_ports':[],'revision':0,'updated':None}
    item=existing[0]
    item['tags']=json.loads(item['tags']);item['expected_ports']=json.loads(item['expected_ports'])
    return item


def enrich(item, asset):
    item['metadata']=metadata_for(item)
    item['findings']=classify(item)
    item['expected']=item['port'] in asset['expected_ports']
    for finding in item['findings']:
        finding['meaning'],finding['next_step']=GUIDANCE[finding['category']]
    return item


def focused_comparison(scan,read=rows):
    if not scan or not scan.get('parent_scan'): return None
    previous=read('SELECT * FROM scans WHERE id=?',(scan['parent_scan'],))
    if not previous:return None
    hosts=set(json.loads(scan['targets']));ports=set(json.loads(scan['ports']))
    old={(x['host'],x['port']) for x in read('SELECT host,port FROM observations WHERE scan_id=?',(previous[0]['id'],)) if x['host'] in hosts and x['port'] in ports}
    current={(x['host'],x['port']) for x in read('SELECT host,port FROM observations WHERE scan_id=?',(scan['id'],))}
    complete=scan['status']=='complete' and previous[0]['status']=='complete'
    return {'parent_scan':scan['parent_scan'],'comparable':complete,
            'still_observed':[{'host':h,'port':p} for h,p in sorted(current&old)],
            'new':[{'host':h,'port':p} for h,p in sorted(current-old)] if complete else [],
            'not_observed':[{'host':h,'port':p} for h,p in sorted(old-current)] if complete else []}


def observation_data(q,connection=None,all_results=False):
    read = (lambda sql,params=():[dict(r) for r in connection.execute(sql,params)]) if connection is not None else rows
    term=q.get('q',[''])[0].strip()
    terms=parse_query(term)
    sort=q.get('sort',['ip'])[0]
    reference=dt.datetime.now(dt.timezone.utc)
    scan = q.get('scan',['latest'])[0]
    limit = 32768 if all_results else min(max(int(q.get('limit',['100'])[0]),1),2000)
    offset = 0 if all_results else max(int(q.get('offset',['0'])[0]),0)
    selected = next(iter(read('SELECT * FROM scans ORDER BY id DESC LIMIT 1')),None) if scan == 'latest' else next(iter(read('SELECT * FROM scans WHERE id=?',(int(scan),))),None)
    sid = selected['id'] if selected else 0
    category = q.get('category',['all'])[0]
    if category not in ('all',*PRESETS):
        raise ValueError('Unknown category.')
    # Filter before pagination so the count and page always describe the same data.
    all_items = read('SELECT host,port,service,banner,observed,metadata FROM observations WHERE scan_id=? ORDER BY host,port',(sid,))
    category_names = {'cameras':'Possible camera interface','telnet':'Possible Telnet','remote':'Remote access candidate',
                      'web':'Web interface candidate','file':'File sharing or transfer candidate'}
    items = []
    assets={host:asset_for(host,read) for host in {r['host'] for r in all_items}}
    for item in all_items:
        enrich(item,assets[item['host']])
        if category in category_names and not any(f['category']==category_names[category] for f in item['findings']):
            continue
        if not matches(item,assets[item['host']],terms,reference):
            continue
        items.append(item)
    items=sort_items(items,assets,sort)
    view = 'services' if all_results else q.get('view',['services'])[0]
    if view not in ('services','devices'): raise ValueError('Unknown results view.')
    hosts = list(dict.fromkeys(r['host'] for r in items))
    page_items = items[offset:offset+limit]
    page_total = len(items)
    page_size = limit
    if view == 'devices':
        page_size = min(limit,20)
        selected_hosts = set(hosts[offset:offset+page_size])
        page_items = [r for r in items if r['host'] in selected_hosts]
        page_total = len(hosts)
    return {'observations':page_items, 'scan_id':sid, 'scan':scan_metadata(selected,read),
                      'limit':limit,'offset':offset,'matching':len(items),'matching_hosts':len(hosts),
                      'page_total':page_total,'page_size':page_size,'view':view,'assets':{host:assets[host] for host in {r['host'] for r in page_items}},'rescan_comparison':focused_comparison(selected,read),
                      'sort':sort,'open_total':len(all_items),'hosts_total':len({r['host'] for r in all_items})}


class ScopeglassHTTPServer(ThreadingHTTPServer):
    # Join in-flight requests before releasing database ownership on shutdown.
    daemon_threads=False


class Handler(BaseHTTPRequestHandler):
    server_version = 'Scopeglass/'+VERSION

    def setup(self):
        super().setup()
        self.connection.settimeout(15)
        self.auth_session=None

    def end_headers(self):
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Permissions-Policy','camera=(), microphone=(), geolocation=()')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        super().end_headers()

    def guard(self,write=False):
        port=self.server.server_port
        origin=CONFIG.get('public_origin',f'http://127.0.0.1:{port}')
        authority=urlparse(origin).netloc.lower()
        origins={origin}
        hosts={authority}
        if origin.startswith('https://') and ':' not in authority:hosts.add(authority+':443')
        if origin.startswith('http://'):
            hosts.update((f'127.0.0.1:{port}',f'localhost:{port}'))
            origins.update('http://'+host for host in hosts)
        if urlparse(self.path).path=='/healthz':hosts.update((f'127.0.0.1:{port}',f'localhost:{port}'))
        if len(self.headers.get_all('Host',[]))!=1 or self.headers.get('Host','').lower() not in hosts:
            raise access.AccessError('Unrecognized host. Open the configured Scopeglass URL.',421)
        if not access.enabled(CONFIG) and not ipaddress.ip_address(self.client_address[0]).is_loopback:
            raise access.AccessError('Password-free access is limited to this computer.',403)
        if write and (self.headers.get('Sec-Fetch-Site')=='cross-site' or (self.headers.get('Origin') is not None and self.headers['Origin'] not in origins)):
            raise access.AccessError('Cross-origin write requests are not accepted.',403)
        with db() as c:self.auth_session=access.session(c,self.headers.get('Cookie'),CONFIG) if access.enabled(CONFIG) else None
        public=urlparse(self.path).path in ('/','/index.html','/healthz','/api/auth/status') if not write else self.path=='/api/auth/login'
        if access.enabled(CONFIG) and not public:
            if not self.auth_session:raise access.AccessError('Sign in to continue. Your unsaved edits are retained.',401)
            if write and not hmac.compare_digest(self.headers.get('X-Scopeglass-CSRF',''),self.auth_session['csrf']):
                raise access.AccessError('Your sign-in state changed. Sign in again before continuing.',403)

    def access_status(self):
        if not access.enabled(CONFIG):return {'enabled':False,'authenticated':True,'username':None,'csrf':None,'expires':None}
        if not self.auth_session:return {'enabled':True,'authenticated':False}
        with db() as c:user=access.account(c)
        return {'enabled':True,'authenticated':True,'username':user['username'],'csrf':self.auth_session['csrf'],'expires':self.auth_session['expires']}

    def log_message(self, fmt, *args):
        print('%s %s' % (self.address_string(), fmt % args))

    def send(self, obj, status=200, headers=None):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Cache-Control','no-store')
        if not access.enabled(CONFIG) or self.auth_session:
            self.send_header('X-Scopeglass-Epoch',current_epoch())
        for key,value in (headers or {}).items():self.send_header(key,value)
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Content-Length',str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        if self.headers.get_content_type() != 'application/json':
            raise ValueError('Use application/json for requests.')
        length = int(self.headers.get('Content-Length','0'))
        maximum=dataops.MAX_ARCHIVE+65536 if self.path in ('/api/data/preview','/api/data/apply') else 32768
        if not 0 < length <= maximum:
            raise ValueError('Request body exceeds the allowed size (16 MiB for archives; 32 KiB otherwise).')
        data = json.loads(self.rfile.read(length),parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Non-finite JSON numbers are not accepted.')))
        if not isinstance(data, dict):
            raise ValueError('Request body must be a JSON object.')
        return data

    def do_GET(self):
        try:
            with LOCK:
                self.guard()
                self.get()
        except access.AccessError as error:
            self.send({'error':str(error)},error.status)
        except (ValueError, KeyError, TypeError, RecursionError, OverflowError) as error:
            self.send({'error':str(error)}, 400)

    def get(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == '/healthz':return self.send({'ok':True,'version':VERSION})
        if u.path == '/api/auth/status':return self.send(self.access_status())
        if u.path == '/api/deployment':
            return self.send({'version':VERSION,'origin':CONFIG.get('public_origin',f'http://127.0.0.1:{self.server.server_port}'),'authentication':access.enabled(CONFIG),'listen_host':CONFIG.get('listen_host','127.0.0.1'),'listen_port':self.server.server_port,'allowed_cidrs':CONFIG['allowed_cidrs'],'database':DB,'session_hours':12,'python':platform.python_version(),'sqlite':sqlite3.sqlite_version})
        if u.path == '/api/status':
            with LOCK:
                state = STATE.copy()
            return self.send({'version':VERSION,'state':state,'latest':latest(),'allowed_cidrs':CONFIG['allowed_cidrs']})
        if u.path == '/api/networks':
            return self.send(local_networks())
        if u.path == '/api/presets':
            return self.send({'presets':PRESETS})
        if u.path == '/api/scans':
            return self.send({'scans':rows('SELECT * FROM scans ORDER BY id DESC LIMIT 100')})
        if u.path == '/api/baselines':
            return self.send({'baselines':rows('SELECT * FROM baselines ORDER BY id DESC')})
        if u.path == '/api/schedules':
            items = rows('SELECT s.*,r.status AS last_status,r.comparison_status FROM schedules s LEFT JOIN scans r ON r.id=s.last_scan WHERE s.deleted=0 ORDER BY s.id')
            return self.send({'schedules':[dict(x,targets=json.loads(x['targets']),ports=json.loads(x['ports'])) for x in items]})
        if u.path == '/api/changes':
            state = q.get('state',['unreviewed'])[0]
            if state not in ('unreviewed','reviewed','all'): raise ValueError('Unknown inbox filter.')
            where = 'WHERE reviewed IS NULL' if state=='unreviewed' else 'WHERE reviewed IS NOT NULL' if state=='reviewed' else ''
            offset = max(0,int(q.get('offset',['0'])[0]))
            total = rows('SELECT count(*) n FROM changes '+where)[0]['n']
            items = rows('SELECT * FROM changes '+where+' ORDER BY id DESC LIMIT 30 OFFSET ?',(offset,))
            return self.send({'changes':[dict(x,evidence=json.loads(x['evidence'])) for x in items], 'total':total,'offset':offset,'limit':30,
                              'unreviewed':rows('SELECT count(*) n FROM changes WHERE reviewed IS NULL')[0]['n']})
        if u.path == '/api/views':
            return self.send({'views':[{**x,'settings':json.loads(x['settings'])} for x in rows('SELECT * FROM saved_views ORDER BY name COLLATE NOCASE')]})
        if u.path == '/api/device':
            host=str(ipaddress.IPv4Address(q.get('host',[''])[0]))
            selected=rows('SELECT * FROM scans WHERE id=?',(int(q.get('scan',['0'])[0]),))
            if not selected or host not in json.loads(selected[0]['targets']):
                return self.send({'error':'This address was not included in the selected scan.'},404)
            asset=asset_for(host)
            services=[enrich(x,asset) for x in rows('SELECT host,port,service,banner,observed,metadata FROM observations WHERE scan_id=? AND host=? ORDER BY port',(selected[0]['id'],host))]
            return self.send({'asset':asset,'services':services,'scan':scan_metadata(selected[0])})
        if u.path == '/api/observations':
            return self.send(observation_data(q))
        if u.path == '/api/compare':
            baseline = rows('SELECT * FROM baselines WHERE id=?',(int(q.get('baseline',['0'])[0]),))
            selected = q.get('scan',['latest'])[0]
            target = latest() if selected=='latest' else next(iter(rows('SELECT * FROM scans WHERE id=?',(int(selected),))),None)
            if not baseline or not target:
                return self.send({'error':'Baseline or current scan missing.'},404)
            previous = rows('SELECT * FROM scans WHERE id=?',(baseline[0]['scan_id'],))[0]
            if target['status'] != 'complete' or previous['status'] != 'complete':
                return self.send({'error':'Comparison needs two completed scans. Partial results cannot establish missing services.'},409)
            if set(json.loads(target['targets'])) != set(json.loads(previous['targets'])) or set(json.loads(target['ports'])) != set(json.loads(previous['ports'])):
                return self.send({'error':'Scan scopes differ. Compare the same hosts and ports to avoid misleading missing-service results.'},409)
            old = {(r['host'],r['port']) for r in rows('SELECT host,port FROM observations WHERE scan_id=?',(baseline[0]['scan_id'],))}
            new = {(r['host'],r['port']) for r in rows('SELECT host,port FROM observations WHERE scan_id=?',(target['id'],))}
            return self.send({'baseline':baseline[0],'current_scan':target['id'],
                              'new':[{'host':h,'port':p} for h,p in sorted(new-old)],
                              'missing':[{'host':h,'port':p} for h,p in sorted(old-new)]})
        if u.path == '/api/data/status':
            with db() as c:
                c.execute('BEGIN')
                return self.send({'counts':{table:c.execute(f'SELECT count(*) FROM {table}').fetchone()[0] for table in dataops.TABLES}})
        if u.path == '/api/report':
            with db() as c:
                c.execute('BEGIN')
                return self.send(observation_data(q,c,True))
        if u.path == '/api/export':
            return self.send(export_snapshot())
        if u.path in ('/','/index.html'):
            data = (ROOT/'static'/'index.html').read_bytes()
            self.send_response(200)
            self.send_header('Content-Type','text/html; charset=utf-8')
            self.send_header('Cache-Control','no-store')
            self.send_header('Content-Length',str(len(data)))
            self.end_headers()
            return self.wfile.write(data)
        self.send_error(404)

    def do_POST(self):
        with LOCK:
            self.post()

    def post(self):
        try:
            self.guard(True)
            if self.path in ('/api/auth/login','/api/auth/password'):access.LIMITER.check(self.client_address[0])
            data = self.body()
            if self.path=='/api/auth/login':
                if not access.enabled(CONFIG):raise ValueError('Login is not enabled for this local installation.')
                with db() as c:result,token=access.login(c,data.get('username'),data.get('password'),self.auth_session)
                with db() as c:self.auth_session=access.session(c,access.cookie_header(token,CONFIG),CONFIG)
                return self.send(result,headers={'Set-Cookie':access.cookie_header(token,CONFIG)})
            if self.path!='/api/preview' and self.headers.get('X-Scopeglass-Epoch')!=current_epoch():
                raise monitoring.Conflict('This dataset changed or the client is outdated. Reload Scopeglass before writing data.')
            if self.path=='/api/auth/logout':
                if self.auth_session:
                    with db() as c:c.execute('DELETE FROM auth_sessions WHERE token_hash=?',(self.auth_session['token_hash'],))
                return self.send({'ok':True},headers={'Set-Cookie':access.cookie_header('',CONFIG,True)})
            if self.path=='/api/auth/password':
                if not access.enabled(CONFIG):raise ValueError('Enable login using --setup before changing the administrator passphrase.')
                with db() as c:
                    user=access.account(c)
                    if not access.password_matches(data.get('current_password'),user['password_hash']):raise access.AccessError('Current passphrase is incorrect.',400)
                    access.set_password(c,user['username'],data.get('new_password'))
                    token,csrf,expires=access.issue_session(c)
                with db() as c:self.auth_session=access.session(c,access.cookie_header(token,CONFIG),CONFIG)
                return self.send(self.access_status(),headers={'Set-Cookie':access.cookie_header(token,CONFIG)})
            if self.path in ('/api/data/preview','/api/data/apply'):
                if STATE['running']:raise monitoring.Conflict('Wait for the active scan to finish or stop it before data maintenance.')
                action=data.get('action')
                if action not in ('restore','cleanup','fresh'):raise ValueError('Choose restore, cleanup, or fresh.')
                restored=None;warnings=[]
                if action=='restore':
                    restored,warnings=dataops.validate_archive(data.get('archive'),PRESETS)
                    options={'archive':data['archive']}
                elif action=='cleanup':options={'days':data.get('days')}
                else:options={}
                with db() as c:
                    c.execute('BEGIN IMMEDIATE')
                    snapshot=export_snapshot(c);fingerprint=dataops.snapshot_hash(snapshot)
                    remove=[];protected=0
                    if action=='cleanup':
                        if self.path.endswith('/preview'):
                            remove,protected=dataops.cleanup_plan(snapshot,options['days'])
                        else:remove=data.get('scan_ids',[])
                        options['scan_ids']=remove
                    if self.path.endswith('/preview'):
                        counts={key:len(value) for key,value in (restored or {k:[] for k in dataops.TABLES}).items()}
                        if action=='cleanup':
                            remove_set=set(remove)
                            counts={key:sum(1 for r in snapshot[key] if (r['id'] if key=='scans' else r['scan_id']) in remove_set) for key in ('scans','observations','checks')}
                        if action=='fresh':counts={key:len(snapshot[key]) for key in dataops.TABLES}
                        token=dataops.sign(action,options,fingerprint)
                        return self.send({'action':action,'token':token,'counts':counts,'current_counts':{key:len(snapshot[key]) for key in dataops.TABLES},'scan_ids':remove,'protected':protected,'warnings':warnings,'expires_in':600})
                    dataops.verify(data.get('token'),action,options,fingerprint)
                    expected={'restore':'RESTORE','cleanup':'DELETE OLD SCANS','fresh':'FRESH START'}[action]
                    if data.get('confirmation')!=expected:raise ValueError('Type '+expected+' to confirm this operation.')
                    backup=dataops.safety_backup(DB)
                    if action=='cleanup':
                        for sid in remove:
                            c.execute('DELETE FROM observations WHERE scan_id=?',(sid,));c.execute('DELETE FROM checks WHERE scan_id=?',(sid,));c.execute('DELETE FROM scans WHERE id=?',(sid,))
                    else:dataops.replace_data(c,restored if action=='restore' else {key:[] for key in dataops.TABLES})
                if action!='cleanup':
                    STATE.update(running=False,completed=0,total=0,error='',scan_id=None,cancelling=False);CANCEL.clear()
                return self.send({'ok':True,'action':action,'backup':backup,'message':'Data operation completed. The previous database was saved before changes.'})
            if self.path == '/api/schedules/run':
                sid = schedule_tick(requested=data.get('id'),revision=data.get('revision')) if data.get('id') is not None else None
                if sid is None: raise ValueError('Choose a saved schedule.')
                return self.send({'scan_id':sid},202)
            if self.path in ('/api/schedules','/api/schedules/pause','/api/schedules/resume','/api/schedules/delete'):
                action = 'save' if self.path=='/api/schedules' else self.path.rsplit('/',1)[1]
                with LOCK:
                    with db() as c:
                        c.execute('BEGIN IMMEDIATE')
                        sid = monitoring.edit_schedule(c,data,action,plan_scan)
                return self.send({'id':sid})
            if self.path == '/api/changes/review':
                ids, reviewed = data.get('ids'),data.get('reviewed')
                if not isinstance(ids,list) or not 1<=len(ids)<=30 or any(type(x) is not int for x in ids) or type(reviewed) is not bool:
                    raise ValueError('Choose 1–30 change IDs and a boolean reviewed state.')
                with db() as c:
                    c.executemany('UPDATE changes SET reviewed=? WHERE id=?',[(now() if reviewed else None,x) for x in ids])
                return self.send({'ok':True})
            if self.path in ('/api/views','/api/views/delete'):
                view_id=data.get('id')
                with db() as c:
                    c.execute('BEGIN IMMEDIATE')
                    existing=c.execute('SELECT * FROM saved_views WHERE id=?',(view_id,)).fetchone() if view_id is not None else None
                    if view_id is not None and (not existing or existing['revision']!=data.get('revision')):
                        return self.send({'error':'This saved view changed or was removed. Refresh saved views before editing it.'},409)
                    if self.path == '/api/views/delete':
                        if existing is None:raise ValueError('Select a saved view to delete.')
                        c.execute('DELETE FROM saved_views WHERE id=?',(view_id,))
                        return self.send({'ok':True})
                    name=data.get('name','')
                    if not isinstance(name,str):raise ValueError('View name must be text.')
                    name=name.strip()
                    settings=data.get('settings',{})
                    if not name or len(name)>80:raise ValueError('Use a view name of 1–80 characters.')
                    if not isinstance(settings,dict):raise ValueError('View settings must be an object.')
                    clean={'q':settings.get('q',''),'category':settings.get('category','all'),'sort':settings.get('sort','ip'),'view':settings.get('view','devices'),'scan':str(settings.get('scan','latest'))}
                    parse_query(clean['q'])
                    if clean['category'] not in ('all',*PRESETS) or clean['sort'] not in SORTS or clean['view'] not in ('devices','services'):
                        raise ValueError('Invalid saved-view filters or layout.')
                    if clean['scan']!='latest' and not c.execute('SELECT id FROM scans WHERE id=?',(int(clean['scan']),)).fetchone():
                        raise ValueError('The pinned scan does not exist.')
                    if c.execute('SELECT id FROM saved_views WHERE name=? AND id!=?',(name,view_id or -1)).fetchone():
                        return self.send({'error':'That view name already exists. Choose it to update it, or use a different name.'},409)
                    if existing:
                        c.execute('UPDATE saved_views SET name=?,settings=?,revision=revision+1,updated=? WHERE id=?',(name,json.dumps(clean),now(),view_id))
                    else:
                        view_id=c.execute('INSERT INTO saved_views(name,settings,revision,updated) VALUES(?,?,1,?)',(name,json.dumps(clean),now())).lastrowid
                return self.send({'id':view_id})
            if self.path == '/api/device':
                host=str(ipaddress.IPv4Address(data.get('host','')))
                if not rows('SELECT id FROM observations WHERE host=? LIMIT 1',(host,)):
                    raise ValueError('Only observed devices can be annotated.')
                name=data.get('name','');notes=data.get('notes','');tags=data.get('tags',[]);expected=data.get('expected_ports',[])
                if not isinstance(name,str) or len(name)>120 or not isinstance(notes,str) or len(notes)>4000:
                    raise ValueError('Name limit: 120 characters. Notes limit: 4000 characters.')
                if not isinstance(tags,list) or len(tags)>12 or any(not isinstance(t,str) or len(t)>32 for t in tags):
                    raise ValueError('Use up to 12 tags of at most 32 characters.')
                if not isinstance(expected,list) or len(expected)>1024 or any(type(port)!=int or not 1<=port<=65535 for port in expected):
                    raise ValueError('Expected ports must be valid TCP port numbers.')
                revision=data.get('revision')
                if type(revision)!=int or revision<0:raise ValueError('A non-negative revision is required.')
                with db() as c:
                    c.execute('BEGIN IMMEDIATE')
                    existing=c.execute('SELECT revision FROM assets WHERE host=?',(host,)).fetchone()
                    if (existing['revision'] if existing else 0)!=revision:
                        return self.send({'error':'This device was edited elsewhere. Your edits are retained; reload the saved device before trying again.'},409)
                    c.execute('INSERT INTO assets(host,name,tags,notes,expected_ports,revision,updated) VALUES(?,?,?,?,?,?,?) ON CONFLICT(host) DO UPDATE SET name=excluded.name,tags=excluded.tags,notes=excluded.notes,expected_ports=excluded.expected_ports,revision=excluded.revision,updated=excluded.updated',
                              (host,name.strip(),json.dumps(sorted(set(t.strip() for t in tags if t.strip()))),notes,json.dumps(sorted(set(expected))),revision+1,now()))
                return self.send({'asset':asset_for(host)})
            parent_scan=None
            if self.path in ('/api/scan','/api/preview','/api/rescan'):
                if self.path == '/api/rescan':
                    host=str(ipaddress.IPv4Address(data.get('host','')))
                    parent_scan=int(data['scan_id'])
                    original=rows('SELECT * FROM scans WHERE id=?',(parent_scan,))
                    if not original or host not in json.loads(original[0]['targets']):
                        raise ValueError('Rescan target must belong to the source scan.')
                    source_ports=json.loads(original[0]['ports'])
                    requested=data.get('port')
                    if requested is not None and (type(requested)!=int or requested not in source_ports):
                        raise ValueError('Choose a port that was included in the source scan.')
                    data={'targets':host,'ports':','.join(str(p) for p in ([requested] if requested is not None else source_ports))}
                hosts, ports, preset = plan_scan(data)
                if self.path == '/api/preview':
                    return self.send({'hosts':len(hosts),'ports':ports,'total':len(hosts)*len(ports),
                                      'first':hosts[0],'last':hosts[-1],'preset':preset})
                with LOCK:
                    if STATE['running']:
                        raise monitoring.Conflict('A scan is already running. Cancel it or wait for it to finish.')
                    with db() as c:
                        sid = create_scan(c,hosts,ports,preset,parent_scan)
                    activate_scan(sid,hosts,ports)
                launch_scan(sid,hosts,ports)
                return self.send({'scan_id':sid,'hosts':len(hosts),'ports':len(ports)},202)
            if self.path == '/api/cancel':
                with LOCK:
                    if not STATE['running']:
                        return self.send({'error':'There is no active scan.'},409)
                    CANCEL.set()
                    STATE['cancelling'] = True
                return self.send({'ok':True,'message':'Stopping after in-flight checks finish; saved observations are retained.'},202)
            if self.path == '/api/baselines':
                sid = int(data['scan_id'])
                scan = rows('SELECT status FROM scans WHERE id=?',(sid,))
                if not scan or scan[0]['status'] != 'complete':
                    raise ValueError('Choose a completed scan.')
                with db() as c:
                    c.execute('INSERT INTO baselines(created,note,scan_id) VALUES(?,?,?)',(now(),str(data.get('note',''))[:120],sid))
                return self.send({'ok':True},201)
            self.send({'error':'Unknown endpoint.'},404)
        except access.AccessError as error:
            self.send({'error':str(error)},error.status,{'Retry-After':str(error.retry)} if error.retry else {})
        except OSError as error:
            self.send({'error':'The operation could not save its backup or data: '+str(error)+'. No data replacement was committed.'},500)
        except sqlite3.Error as error:
            self.send({'error':'Database operation failed: '+str(error)},500)
        except monitoring.Conflict as error:
            self.send({'error':str(error)},409)
        except (ValueError, KeyError, TypeError, RecursionError, OverflowError) as error:
            self.send({'error':str(error)},400)


def main():
    global DB, CONFIG
    parser=argparse.ArgumentParser(description='Scopeglass scoped TCP inventory')
    parser.add_argument('--config',default=str(ROOT/'config.json'))
    group=parser.add_mutually_exclusive_group()
    group.add_argument('--setup',action='store_true',help='Guided local or authenticated setup; does not start the server')
    group.add_argument('--set-password',action='store_true',help='Set/reset the administrator passphrase at the server terminal; revokes sessions')
    group.add_argument('--check-config',action='store_true',help='Validate configuration and account readiness without starting or migrating')
    parser.add_argument('--username',default='admin',help='Username for --set-password (default: admin)')
    args=parser.parse_args()
    os.umask(0o077)
    try:
        if args.setup:
            deployment.setup(args.config);return
        CONFIG=deployment.load(args.config);DB=CONFIG['database']
        deployment.check_database(DB)
        if args.check_config:
            ready=not access.enabled(CONFIG)
            if access.enabled(CONFIG) and Path(DB).exists():
                c=sqlite3.connect(Path(DB).as_uri()+'?mode=ro',uri=True)
                try:
                    ready=bool(c.execute('SELECT 1 FROM auth_account WHERE id=1').fetchone())
                except sqlite3.OperationalError:ready=False
                finally:c.close()
            print(json.dumps({'valid':True,'ready':ready,'origin':CONFIG['public_origin'],'authentication':access.enabled(CONFIG),'database':DB,'listen':f"{CONFIG['listen_host']}:{CONFIG['listen_port']}"},indent=2))
            if not ready:raise SystemExit('Create the administrator account with --set-password before starting.')
            return
        Path(DB).parent.mkdir(parents=True,exist_ok=True)
        if args.set_password:
            password=deployment.password_prompt()
            with db() as c:
                access.init_schema(c);access.set_password(c,args.username,password)
            print('Administrator passphrase saved; all previous sessions revoked. Authentication '+('is enabled.' if access.enabled(CONFIG) else 'is disabled in this configuration; run --setup to enable it.'))
            return
        with deployment.database_owner(DB):
            # Reserve the port before migration/recovery can change saved state.
            with ScopeglassHTTPServer((CONFIG['listen_host'],CONFIG['listen_port']),Handler) as http:
                if access.enabled(CONFIG):
                    with db() as c:
                        access.init_schema(c)
                        if not access.account(c):raise SystemExit('Authentication is enabled but no administrator exists. Run with --set-password first.')
                init_db()
                serve(http)
    except (ValueError,OSError,KeyError,TypeError,sqlite3.Error) as error:
        raise SystemExit('Setup error: '+str(error))


def serve(http):
    print(f"Scopeglass v{VERSION} · {CONFIG['public_origin']} · "+('administrator login' if access.enabled(CONFIG) else 'local access, no login'),flush=True)
    stop=threading.Event()
    scheduler=threading.Thread(target=scheduler_loop,args=(stop,),daemon=True)
    scheduler.start()
    def shutdown(signum,frame):
        stop.set();CANCEL.set()
        threading.Thread(target=http.shutdown,daemon=True).start()
    signal.signal(signal.SIGTERM,shutdown)
    signal.signal(signal.SIGINT,shutdown)
    try:http.serve_forever()
    finally:
        stop.set();CANCEL.set();http.server_close()
        scheduler.join()
        # A request finishing during shutdown may have just launched a scan.
        CANCEL.set()
        if SCAN_THREAD is not None:SCAN_THREAD.join()


if __name__=='__main__':main()
