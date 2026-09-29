"""Regression checks for the v0.7.1 correctness review."""
import datetime as dt
from contextlib import contextmanager
import json
import socket
import sqlite3
import threading
import time
import unittest
from unittest.mock import patch
import test_server as base
import searching
import protocols
sg=base.sg


class AuditServerTests(unittest.TestCase):
    setUp=base.ServerTests.setUp
    tearDown=base.ServerTests.tearDown
    api=base.ServerTests.api
    wait_scan=base.ServerTests.wait_scan

    def seed(self):
        with sg.db() as c:
            sid=c.execute("INSERT INTO scans(started,finished,status,targets,ports,checked,total) VALUES(?,?,'complete',?,?,1,2)",(sg.now(),sg.now(),'["127.0.0.1"]','[22,23]')).lastrowid
            c.execute("INSERT INTO checks VALUES(?,?,?,?)",(sid,'127.0.0.1',22,'open'))
            c.execute("INSERT INTO observations(scan_id,host,port,service,banner,observed) VALUES(?,?,?,?,?,?)",(sid,'127.0.0.1',22,'ssh','SSH',sg.now()))
        return sid

    def test_export_remains_one_snapshot_during_concurrent_commit(self):
        sid=self.seed();original=sg.db;changed=[]
        def update(sql):
            if sql.startswith('SELECT * FROM observations') and not changed:
                changed.append(True)
                with sqlite3.connect(sg.DB) as writer:
                    writer.execute('UPDATE scans SET checked=2 WHERE id=?',(sid,))
                    writer.execute('INSERT INTO checks VALUES(?,?,?,?)',(sid,'127.0.0.1',23,'open'))
                    writer.execute('INSERT INTO observations(scan_id,host,port,service,banner,observed) VALUES(?,?,?,?,?,?)',(sid,'127.0.0.1',23,'telnet','login',sg.now()))
        @contextmanager
        def traced():
            with original() as c:
                c.set_trace_callback(update)
                yield c
        with patch.object(sg,'db',traced):snapshot=sg.export_snapshot()
        self.assertEqual(snapshot['scans'][0]['checked'],1)
        self.assertEqual(len(snapshot['checks']),1)
        self.assertEqual(len(snapshot['observations']),1)
        self.assertEqual(sg.export_snapshot()['scans'][0]['checked'],2)
        self.assertEqual(len(sg.export_snapshot()['observations']),2)

    def test_baseline_uses_explicit_selected_scan(self):
        sid=self.seed();self.api('baselines',{'scan_id':sid})
        bid=self.api('baselines')['baselines'][0]['id']
        with sg.db() as c:
            c.execute("INSERT INTO scans(started,status,targets,ports,checked,total) VALUES(?,'complete',?,?,2,2)",(sg.now(),'["127.0.0.1"]','[22,23]'))
        pinned=self.api(f'compare?baseline={bid}&scan={sid}')
        self.assertEqual(pinned['current_scan'],sid);self.assertEqual(pinned['missing'],[])
        self.assertEqual(len(self.api(f'compare?baseline={bid}')['missing']),1)


class AuditEvidenceTests(unittest.TestCase):
    def test_fragmented_telnet_negotiation(self):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen()
        def serve():
            conn,_=listener.accept()
            with conn:
                for piece in (b'\xff',b'\xfb',b'\x01'):
                    try:conn.sendall(piece);time.sleep(.02)
                    except OSError:break
            listener.close()
        thread=threading.Thread(target=serve);thread.start()
        result=protocols.inspect_service('127.0.0.1',listener.getsockname()[1]);thread.join(1)
        self.assertEqual(result['metadata']['protocol'],'telnet')
        self.assertEqual(result['metadata']['identification'],'verified')

    def test_plain_search_excludes_internal_annotation_fields(self):
        item={'host':'127.0.0.1','port':22,'service':'ssh','banner':'','metadata':{},'expected':False,'findings':[]}
        asset={'name':'Workshop','notes':'Verify owner','tags':['lab'],'revision':987654,'expected_ports':[54321]}
        for query in ('987654','54321'):
            self.assertFalse(searching.matches(item,asset,searching.parse_query(query),dt.datetime.now(dt.timezone.utc)))
        self.assertTrue(searching.matches(item,asset,searching.parse_query('workshop lab'),dt.datetime.now(dt.timezone.utc)))
