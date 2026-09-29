"""Process-level release gates. Temporary databases and loopback listeners only."""
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import deployment


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        return sock.getsockname()[1]


class StartupTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.folder=Path(self.tmp.name);self.database=self.folder/'data.db'
        self.config=self.folder/'config.json';self.port=free_port()
        self.write_config()

    def write_config(self):
        self.config.write_text(json.dumps({'listen_host':'127.0.0.1','listen_port':self.port,'database':str(self.database),'allowed_cidrs':['127.0.0.0/8']}))

    def invoke(self,*args):
        return subprocess.run([sys.executable,str(ROOT/'server.py'),'--config',str(self.config),*args],capture_output=True,text=True,timeout=15)

    def start(self,slow=False):
        command=[sys.executable,str(ROOT/'server.py')]
        if slow:
            code="import sys,time;sys.path.insert(0,sys.argv.pop(1));import server;server.probe=lambda *args: (time.sleep(.5) or {'outcome':'refused'});server.main()"
            command=[sys.executable,'-c',code,str(ROOT)]
        log=open(self.folder/f'process-{time.time_ns()}.log','w+')
        self.addCleanup(log.close)
        process=subprocess.Popen([*command,'--config',str(self.config)],stdout=log,stderr=log)
        def stop():
            if process.poll() is None:process.kill();process.wait(timeout=10)
        self.addCleanup(stop)
        for _ in range(100):
            if process.poll() is not None:
                log.seek(0);self.fail(log.read())
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{self.port}/healthz',timeout=.3) as response:
                    if response.status==200:return process
            except OSError:time.sleep(.05)
        self.fail('Server did not become ready')

    def seed_running(self):
        with sqlite3.connect(self.database) as c:
            c.executescript((ROOT/'tests/fixtures/v0.8.sql').read_text())
            c.execute("UPDATE scans SET status='running',finished=NULL WHERE id=1")

    def test_duplicate_server_does_not_interrupt_existing_scan(self):
        first=self.start()
        with sqlite3.connect(self.database) as c:
            c.execute("INSERT INTO scans(started,status,targets,ports,total) VALUES('2026-09-01T00:00:00+00:00','running','[\"127.0.0.1\"]','[22]',1)")
        self.port=free_port();self.write_config() # A different port must still be refused.
        result=self.invoke()
        self.assertNotEqual(result.returncode,0);self.assertIn('already in use',result.stderr)
        with sqlite3.connect(self.database) as c:self.assertEqual(c.execute('SELECT status FROM scans').fetchone()[0],'running')
        self.assertIsNone(first.poll())

    def test_busy_port_leaves_legacy_database_untouched(self):
        self.seed_running();before=self.database.read_bytes()
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1',self.port));occupied.listen()
            result=self.invoke()
        self.assertNotEqual(result.returncode,0);self.assertIn('Setup error:',result.stderr)
        self.assertEqual(before,self.database.read_bytes())
        with deployment.database_owner(self.database):pass # Failure released ownership.

    def test_crash_releases_ownership_and_restart_recovers_scan(self):
        self.seed_running();first=self.start()
        with sqlite3.connect(self.database) as c:c.execute("UPDATE scans SET status='running',finished=NULL WHERE id=1")
        first.kill();first.wait(timeout=10)
        self.assertTrue(Path(str(self.database)+'.lock').exists())
        self.start()
        with sqlite3.connect(self.database) as c:
            self.assertEqual(c.execute('SELECT status FROM scans WHERE id=1').fetchone()[0],'interrupted')
            self.assertGreater(c.execute('SELECT COUNT(*) FROM observations').fetchone()[0],0)

    def test_future_database_refused_without_downgrade_or_writes(self):
        self.seed_running()
        with sqlite3.connect(self.database) as c:c.execute('PRAGMA user_version=100')
        before=self.database.read_bytes()
        for args in ((),('--check-config',),('--set-password',)):
            result=self.invoke(*args)
            self.assertNotEqual(result.returncode,0);self.assertIn('newer than',result.stderr)
            self.assertEqual(before,self.database.read_bytes())

    def test_setup_cannot_replace_live_configuration(self):
        self.start();before=self.config.read_bytes()
        answers=['1',str(self.port),str(self.database),'127.0.0.0/8','REPLACE']
        with patch('builtins.input',side_effect=answers),self.assertRaisesRegex(ValueError,'already in use'):
            deployment.setup(self.config)
        self.assertEqual(before,self.config.read_bytes())
        self.assertFalse(list(self.folder.glob('config.json.before-*')))

    @unittest.skipIf(os.name=='nt','Windows terminate forcibly stops the process; Unix SIGTERM is the graceful path.')
    def test_sigterm_waits_for_scan_to_save_then_releases_ownership(self):
        process=self.start(slow=True);base=f'http://127.0.0.1:{self.port}'
        with urllib.request.urlopen(base+'/api/status') as response:epoch=response.headers['X-Scopeglass-Epoch']
        request=urllib.request.Request(base+'/api/scan',data=json.dumps({'targets':'127.0.0.0/26','ports':'22'}).encode(),headers={'Content-Type':'application/json','X-Scopeglass-Epoch':epoch})
        with urllib.request.urlopen(request) as response:sid=json.load(response)['scan_id']
        process.terminate();process.wait(timeout=15)
        self.assertEqual(process.returncode,0)
        with sqlite3.connect(self.database) as c:
            row=c.execute('SELECT status,checked,total FROM scans WHERE id=?',(sid,)).fetchone()
            self.assertEqual(row[0],'cancelled');self.assertLess(row[1],row[2])
            self.assertEqual(row[1],c.execute('SELECT COUNT(*) FROM checks WHERE scan_id=?',(sid,)).fetchone()[0])
        with deployment.database_owner(self.database):pass
