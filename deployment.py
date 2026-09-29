"""Validated configuration and guided, terminal-owned setup."""
import datetime as dt
from contextlib import contextmanager
import errno
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
from urllib.parse import urlsplit
import access

DEFAULT_NETWORKS=['127.0.0.0/8','10.0.0.0/8','172.16.0.0/12','192.168.0.0/16']
SCHEMA_VERSION=9


def check_schema(connection):
    version=connection.execute('PRAGMA user_version').fetchone()[0]
    if version>SCHEMA_VERSION:
        raise ValueError(f'Database schema {version} is newer than this application supports ({SCHEMA_VERSION}). Use the newer application or restore a pre-upgrade backup at a new filename.')


def check_database(path):
    if Path(path).exists():
        connection=sqlite3.connect(Path(path).resolve().as_uri()+'?mode=ro',uri=True)
        try:check_schema(connection)
        finally:connection.close()


@contextmanager
def database_owner(path):
    """One server per canonical database path; OS releases ownership on exit/crash.

    Keep the sidecar: unlinking it lets new processes lock a different inode.
    Use local storage; hard-linked databases and network filesystems are unsupported.
    """
    lock_path=Path(str(Path(path).resolve())+'.lock')
    lock_path.parent.mkdir(parents=True,exist_ok=True)
    descriptor=os.open(lock_path,os.O_RDWR|os.O_CREAT,0o600)
    try:
        try:
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(descriptor,msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in (errno.EACCES,errno.EAGAIN,errno.EDEADLK):
                raise ValueError('This database is already in use by another Scopeglass process. Stop that process before starting or configuring this installation. Do not delete its .lock file.') from error
            raise
        yield
    finally:
        # Closing releases the OS lock, including on a failed startup.
        os.close(descriptor)


def normalize(raw):
    if not isinstance(raw,dict):raise ValueError('Configuration must be a JSON object.')
    config=dict(raw);host=config.get('listen_host','127.0.0.1');port=config.get('listen_port',8765)
    if not isinstance(host,str):raise ValueError('listen_host must be IPv4 text.')
    if host=='localhost':host='127.0.0.1'
    try:address=ipaddress.IPv4Address(host)
    except (ValueError,TypeError):raise ValueError('listen_host must be an IPv4 address, such as 127.0.0.1 or 0.0.0.0.')
    if type(port) is not int or not 1<=port<=65535:raise ValueError('listen_port must be an integer from 1 to 65535.')
    networks=config.get('allowed_cidrs')
    if not isinstance(networks,list) or not 1<=len(networks)<=64:raise ValueError('Configure 1–64 allowed IPv4 CIDRs.')
    networks=[str(ipaddress.IPv4Network(x,strict=False)) for x in networks if isinstance(x,str)]
    if len(networks)!=len(config['allowed_cidrs']):raise ValueError('allowed_cidrs entries must be IPv4 text.')
    auth=config.get('auth',{'enabled':False})
    if not isinstance(auth,dict) or type(auth.get('enabled',False)) is not bool:raise ValueError('auth.enabled must be true or false.')
    if set(auth)-{'enabled'}:raise ValueError('auth supports only the enabled setting in this release.')
    auth={'enabled':auth.get('enabled',False)}
    if not auth['enabled'] and not address.is_loopback:raise ValueError('A non-loopback listener requires auth.enabled=true. Run --setup or use the authenticated deployment example.')
    origin=config.get('public_origin',f'http://{address}:{port}')
    if not isinstance(origin,str):raise ValueError('public_origin must be a full http/https origin.')
    parsed=urlsplit(origin)
    try:origin_port=parsed.port
    except ValueError:raise ValueError('Invalid public_origin port.')
    if origin_port is not None and not 1<=origin_port<=65535:raise ValueError('Invalid public_origin port.')
    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ('','/') or parsed.query or parsed.fragment or not re.fullmatch(r'[A-Za-z0-9.:-]+',parsed.netloc):
        raise ValueError('public_origin must contain only scheme, hostname, and optional port; no path or credentials.')
    hostname=parsed.hostname.lower()
    try:local_origin=ipaddress.ip_address(hostname).is_loopback
    except ValueError:local_origin=hostname=='localhost'
    if parsed.scheme=='http' and not local_origin:raise ValueError('Shared access requires an https:// public_origin and an HTTPS reverse proxy.')
    if not auth['enabled'] and (not local_origin or parsed.scheme!='http'):raise ValueError('Password-free access is limited to local HTTP. Enable authentication for a reverse proxy.')
    if not auth['enabled'] and (origin_port or 80)!=port:raise ValueError('Local public_origin must use listen_port.')
    netloc=hostname+(f':{origin_port}' if origin_port and origin_port!=({'https':443,'http':80}[parsed.scheme]) else '')
    database=config.get('database','./data/scopeglass.db')
    if not isinstance(database,str) or not database.strip():raise ValueError('database must be a file path.')
    config.update(listen_host=str(address),listen_port=port,allowed_cidrs=networks,auth=auth,public_origin=f'{parsed.scheme}://{netloc}',database=str(Path(database).expanduser().resolve()))
    return config


def load(path):
    return normalize(json.loads(Path(path).read_text(encoding='utf-8')))


def password_prompt():
    password=getpass.getpass('New passphrase (15–128 characters): ')
    if password!=getpass.getpass('Repeat passphrase: '):raise ValueError('Passphrases do not match. Nothing was saved.')
    # Validate before any configuration or database write.
    access.password_hash(password)
    return password


def setup(path):
    path=Path(path)
    prior=json.loads(path.read_text()) if path.exists() else {}
    print('Scopeglass setup — all data stays on this server.\n1. This computer, no login\n2. This computer, administrator login\n3. Shared access through an HTTPS reverse proxy')
    choice=input('Choose 1, 2, or 3 [1]: ').strip() or '1'
    if choice not in ('1','2','3'):raise ValueError('Choose 1, 2, or 3.')
    port=int(input(f"Local port [{prior.get('listen_port',8765)}]: ").strip() or prior.get('listen_port',8765))
    database=input(f"Database file [{prior.get('database','./data/scopeglass.db')}]: ").strip() or prior.get('database','./data/scopeglass.db')
    networks=input('Allowed IPv4 CIDRs, comma separated [loopback and private ranges]: ').strip()
    raw={'listen_host':'127.0.0.1','listen_port':port,'database':database,'allowed_cidrs':[x.strip() for x in networks.split(',')] if networks else DEFAULT_NETWORKS.copy(),'auth':{'enabled':choice!='1'},'public_origin':f'http://127.0.0.1:{port}'}
    if choice=='3':raw['public_origin']=input('Public HTTPS origin, for example https://scopeglass.example.com: ').strip()
    config=normalize(raw);username=None;password=None
    if choice!='1':
        username=input('Administrator username [admin]: ').strip() or 'admin'
        if not re.fullmatch(r'[A-Za-z0-9_.-]{3,64}',username):raise ValueError('Username: 3–64 letters, digits, dots, underscores, or hyphens.')
        password=password_prompt()
    if path.exists() and input('Replace this configuration? A copy will be saved. Type REPLACE: ').strip()!='REPLACE':raise ValueError('Setup cancelled; no changes saved.')
    with database_owner(config['database']):
        check_database(config['database'])
        path.parent.mkdir(parents=True,exist_ok=True)
        if path.exists():
            backup=path.with_name(path.name+'.before-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+secrets.token_hex(3));backup.write_bytes(path.read_bytes());os.chmod(backup,0o600)
        temp=path.with_name(path.name+'.tmp-'+secrets.token_hex(4))
        try:
            fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as stream:json.dump(config,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
            if username:
                Path(config['database']).parent.mkdir(parents=True,exist_ok=True)
                c=sqlite3.connect(config['database'])
                try:
                    access.init_schema(c)
                    with c:access.set_password(c,username,password)
                finally:c.close()
            os.replace(temp,path)
        finally:temp.unlink(missing_ok=True)
    print('Configuration saved. Start Scopeglass with --config '+str(path)+'.')
    if choice=='3':print('Configure the HTTPS proxy before opening '+config['public_origin']+'. The scanner remains bound to loopback.')
    return config
