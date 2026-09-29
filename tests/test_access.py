"""Authentication, deployment boundaries, and actual v0.8 database migration."""
import copy
from http.cookies import SimpleCookie
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.request
import urllib.error
import zipfile
import test_server as base
import access
import deployment
sg=base.sg
PASSWORD='Workshop copper lantern river 42'
NEW_PASSWORD='Another quiet mountain workshop 83'


class AccessTests(unittest.TestCase):
    def setUp(self):
        base.ServerTests.setUp(self)
        access.LIMITER.clear()
        sg.CONFIG.update(auth={'enabled':True},public_origin=f'http://127.0.0.1:{self.http.server_port}')
        with sg.db() as c:access.set_password(c,'admin',PASSWORD)
        self.cookie='';self.csrf=''
    tearDown=base.ServerTests.tearDown
    wait_scan=base.ServerTests.wait_scan

    def request(self,path,body=None,headers=None,cookie=None,csrf=None):
        hdr={'Content-Type':'application/json','X-Scopeglass-Epoch':sg.current_epoch(),'Cookie':self.cookie if cookie is None else cookie,'X-Scopeglass-CSRF':self.csrf if csrf is None else csrf,**(headers or {})}
        request=urllib.request.Request(self.url+path,data=None if body is None else json.dumps(body).encode(),headers=hdr)
        try:response=urllib.request.urlopen(request,timeout=6)
        except urllib.error.HTTPError as error:response=error
        with response:
            payload=response.read()
            try:data=json.loads(payload)
            except ValueError:data=payload.decode()
            return response.status,data,response.headers

    def login(self):
        status,data,headers=self.request('auth/login',{'username':'admin','password':PASSWORD})
        self.assertEqual(status,200,data);self.cookie=headers['Set-Cookie'].split(';')[0];self.csrf=data['csrf']
        return data,headers

    def test_all_inventory_and_write_routes_require_login(self):
        for path in ('status','presets','networks','scans','observations','report','export','device?host=127.0.0.1&scan=1','schedules','changes','baselines','views','data/status','deployment'):
            with self.subTest(path=path):self.assertEqual(self.request(path)[0],401)
        for path in ('preview','scan','cancel','device','views','schedules','changes/review','baselines','data/preview','data/apply'):
            with self.subTest(path=path):self.assertEqual(self.request(path,{})[0],401)
        status,data,headers=self.request('auth/status');self.assertEqual(data,{'enabled':True,'authenticated':False});self.assertIsNone(headers['X-Scopeglass-Epoch'])
        with urllib.request.urlopen(self.url.replace('/api/','/healthz')) as r:self.assertTrue(json.load(r)['ok'])
        with urllib.request.urlopen(self.url.replace('/api/','/')) as r:
            self.assertIn('login-form',r.read().decode());self.assertEqual(r.headers['X-Frame-Options'],'DENY');self.assertIn("frame-ancestors 'none'",r.headers['Content-Security-Policy'])

    def test_login_hashed_session_csrf_and_logout(self):
        info,headers=self.login();self.assertIn('HttpOnly',headers['Set-Cookie']);self.assertIn('SameSite=Strict',headers['Set-Cookie']);self.assertNotIn('Secure',headers['Set-Cookie'])
        with sg.db() as c:
            user=access.account(c);sessions=c.execute('SELECT * FROM auth_sessions').fetchall()
            self.assertNotIn(PASSWORD,user['password_hash']);self.assertEqual(len(sessions),1);self.assertNotIn(self.cookie.split('=',1)[1],str(dict(sessions[0])))
        self.assertEqual(self.request('auth/status')[1]['username'],'admin');self.assertEqual(self.request('status')[0],200)
        self.assertEqual(self.request('preview',{'targets':'127.0.0.1','ports':'22'},csrf='wrong')[0],403)
        self.assertEqual(self.request('preview',{'targets':'127.0.0.1','ports':'22'})[0],200)
        old=self.cookie;status,data,headers=self.request('auth/logout',{});self.assertEqual(status,200);self.assertIn('Max-Age=0',headers['Set-Cookie'])
        self.assertEqual(self.request('status',cookie=old)[0],401)

    def test_generic_login_failure_and_rate_limit(self):
        a=self.request('auth/login',{'username':'missing','password':PASSWORD});b=self.request('auth/login',{'username':'admin','password':'wrong'})
        self.assertEqual(a[0],401);self.assertEqual(a[1],b[1])
        for _ in range(3):self.request('auth/login',{'username':'admin','password':'wrong'})
        blocked=self.request('auth/login',{'username':'admin','password':PASSWORD});self.assertEqual(blocked[0],429);self.assertGreater(int(blocked[2]['Retry-After']),0)
        self.assertEqual(self.request('auth/status')[0],200)
        with patch.object(access.time,'monotonic',return_value=access.time.monotonic()+61):self.login()

    def test_password_change_revokes_other_sessions_and_current_stays_signed_in(self):
        self.login();other=self.cookie
        self.cookie='';self.csrf='';self.login()
        self.assertEqual(self.request('auth/password',{'current_password':'wrong','new_password':NEW_PASSWORD})[0],400)
        self.assertEqual(self.request('auth/password',{'current_password':PASSWORD,'new_password':'short'})[0],400)
        code,data,headers=self.request('auth/password',{'current_password':PASSWORD,'new_password':NEW_PASSWORD});self.assertEqual(code,200)
        self.cookie=headers['Set-Cookie'].split(';')[0];self.csrf=data['csrf']
        self.assertEqual(self.request('status')[0],200);self.assertEqual(self.request('status',cookie=other)[0],401)
        with sg.db() as c:self.assertTrue(access.password_matches(NEW_PASSWORD,access.account(c)['password_hash']))

    def test_session_expiration_and_session_limit(self):
        self.login()
        with sg.db() as c:c.execute('UPDATE auth_sessions SET expires=0')
        self.assertEqual(self.request('status')[0],401)
        with sg.db() as c:
            for _ in range(25):access.issue_session(c)
            self.assertEqual(c.execute('SELECT count(*) FROM auth_sessions').fetchone()[0],access.MAX_SESSIONS)

    def test_host_origin_fetch_metadata_and_forwarded_headers(self):
        self.login()
        self.assertEqual(self.request('status',headers={'Host':'evil.example'})[0],421)
        body={'targets':'127.0.0.1','ports':'22'}
        for headers in ({'Origin':'https://evil.example'},{'Origin':'null'},{'Origin':sg.CONFIG['public_origin'].replace('http:','https:')},{'Sec-Fetch-Site':'cross-site'}):
            self.assertEqual(self.request('preview',body,headers=headers)[0],403)
        self.assertEqual(self.request('preview',body,headers={'Origin':sg.CONFIG['public_origin']})[0],200)
        self.assertEqual(self.request('status',headers={'X-Forwarded-Host':'evil.example','X-Forwarded-Proto':'https','X-Forwarded-For':'1.2.3.4'})[0],200)
        sg.CONFIG['public_origin']='https://scopeglass.example.test'
        self.assertEqual(self.request('status')[0],421)
        status,data,headers=self.request('auth/login',{'username':'admin','password':PASSWORD},headers={'Host':'scopeglass.example.test','Origin':'https://scopeglass.example.test'})
        self.assertEqual(status,200);self.assertTrue(headers['Set-Cookie'].startswith('__Host-scopeglass='));self.assertIn('; Secure',headers['Set-Cookie'])

    def test_restore_and_fresh_start_preserve_account_but_export_excludes_secrets(self):
        self.login();archive=self.request('export')[1]
        self.assertFalse(any(key.startswith('auth') for key in archive));self.assertNotIn(PASSWORD,json.dumps(archive));self.assertNotIn(self.csrf,json.dumps(archive))
        with sg.db() as c:before=dict(access.account(c))
        for action in ('fresh','restore'):
            body={'action':action,**({'archive':archive} if action=='restore' else {})}
            status,preview,_=self.request('data/preview',body);self.assertEqual(status,200)
            status,result,_=self.request('data/apply',{**body,'token':preview['token'],'confirmation':'FRESH START' if action=='fresh' else 'RESTORE'});self.assertEqual(status,200,result)
            with sg.db() as c:self.assertEqual(dict(access.account(c)),before)
            self.assertEqual(self.request('auth/status')[1]['username'],'admin')

    def test_local_mode_remains_compatible_and_remote_mode_fails_closed(self):
        sg.CONFIG['auth']['enabled']=False
        self.assertEqual(self.request('status')[0],200);self.assertFalse(self.request('auth/status')[1]['enabled'])
        self.assertEqual(self.request('preview',{'targets':'127.0.0.1','ports':'22'})[0],200)
        self.assertEqual(self.request('status',headers={'Host':'rebinding.example'})[0],421)
        base={'listen_host':'127.0.0.1','listen_port':8765,'database':sg.DB,'allowed_cidrs':['127.0.0.0/8']}
        for changes in ({'listen_host':'0.0.0.0'},{'auth':{'enabled':'yes'}},{'auth':{'enabld':True}},{'public_origin':'https://workshop.example:0','auth':{'enabled':True}},{'public_origin':'http://workshop.example','auth':{'enabled':True}},{'public_origin':'https://host.example/path','auth':{'enabled':True}},{'public_origin':'https://user:password@host.example','auth':{'enabled':True}},{'allowed_cidrs':['::1/128']}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):deployment.normalize({**base,**changes})
        valid=deployment.normalize({**base,'listen_host':'0.0.0.0','auth':{'enabled':True},'public_origin':'https://workshop.example/'})
        self.assertEqual(valid['public_origin'],'https://workshop.example')

    def test_password_hash_salts_validation_and_cli_reset(self):
        first=access.password_hash(PASSWORD);second=access.password_hash(PASSWORD);self.assertNotEqual(first,second);self.assertTrue(access.password_matches(PASSWORD,first));self.assertFalse(access.password_matches('wrong',first))
        for value in ('short','x'*129,None):
            with self.assertRaises(ValueError):access.password_hash(value)
        self.login();config=Path(self.tmp.name)/'config.json';config.write_text(json.dumps({**sg.CONFIG,'database':sg.DB}))
        with patch.object(sys,'argv',['server.py','--config',str(config),'--set-password']),patch('getpass.getpass',side_effect=[NEW_PASSWORD,NEW_PASSWORD]):sg.main()
        self.assertEqual(self.request('status')[0],401)
        with sg.db() as c:self.assertTrue(access.password_matches(NEW_PASSWORD,access.account(c)['password_hash']))


class DeploymentTests(unittest.TestCase):
    def test_guided_setup_and_read_only_config_check(self):
        with tempfile.TemporaryDirectory() as folder:
            config=Path(folder)/'config.json';database=Path(folder)/'db.sqlite3'
            answers=['2','8765',str(database),'127.0.0.0/8','admin']
            with patch('builtins.input',side_effect=answers),patch('getpass.getpass',side_effect=[PASSWORD,PASSWORD]):result=deployment.setup(config)
            self.assertTrue(result['auth']['enabled']);self.assertEqual(result['database'],str(database))
            stamp=database.stat().st_mtime_ns
            out=subprocess.run([sys.executable,str(Path(sg.__file__)),'--config',str(config),'--check-config'],capture_output=True,text=True,timeout=10)
            self.assertEqual(out.returncode,0,out.stderr);self.assertTrue(json.loads(out.stdout)['ready']);self.assertEqual(database.stat().st_mtime_ns,stamp)
            # Cancelling an overwrite does not replace config or account.
            old=config.read_bytes()
            with patch('builtins.input',side_effect=['1','8765',str(database),'','NO']),self.assertRaises(ValueError):deployment.setup(config)
            self.assertEqual(config.read_bytes(),old)

    def test_auth_without_account_stops_before_listen_and_migration(self):
        with tempfile.TemporaryDirectory() as folder:
            config=Path(folder)/'config.json';database=Path(folder)/'db.sqlite3'
            config.write_text(json.dumps({'allowed_cidrs':['127.0.0.0/8'],'database':str(database),'auth':{'enabled':True}}))
            out=subprocess.run([sys.executable,str(Path(sg.__file__)),'--config',str(config)],capture_output=True,text=True,timeout=10)
            self.assertNotEqual(out.returncode,0);self.assertIn('--set-password',out.stderr)
            with sqlite3.connect(database) as c:self.assertFalse(c.execute("SELECT name FROM sqlite_master WHERE name='scans'").fetchone())

    def test_v08_database_upgrade_preserves_all_assessment_tables(self):
        # The bundled fixture is created using the shipped v0.8 schema, without credentials.
        with tempfile.TemporaryDirectory() as folder:
            database=Path(folder)/'legacy.db';fixture=Path(__file__).parent/'fixtures'/'v0.8.sql'
            with sqlite3.connect(database) as c:c.executescript(fixture.read_text())
            original_db,original_config=sg.DB,sg.CONFIG
            try:
                sg.DB=str(database);sg.CONFIG={'allowed_cidrs':['127.0.0.0/8']}
                before=sg.export_snapshot();sg.init_db();sg.init_db();after=sg.export_snapshot()
                for table in sg.dataops.TABLES:self.assertEqual(before[table],after[table],table)
                with sg.db() as c:
                    self.assertEqual(c.execute('PRAGMA user_version').fetchone()[0],9);self.assertIsNone(access.account(c))
                sg.dataops.validate_archive(after,sg.PRESETS)
            finally:sg.DB,sg.CONFIG=original_db,original_config
