import datetime as dt
import json
import threading
import time
import unittest
from unittest.mock import patch
import urllib.error
import test_server as base
sg = base.sg


class MonitoringTests(unittest.TestCase):
    setUp = base.ServerTests.setUp
    tearDown = base.ServerTests.tearDown
    api = base.ServerTests.api
    wait_scan = base.ServerTests.wait_scan

    def source(self, ports='22,23,443'):
        def old(host,port):
            return {'outcome':'open','service':'fixture','banner':'before',
                    'metadata':{'protocol':'ssh' if port==22 else 'telnet' if port==23 else 'https',
                                'identification':'verified','tls':{'sha256':'old'} if port==443 else {}}}
        with patch.object(sg,'probe',side_effect=old):
            sid=self.api('scan',{'targets':'127.0.0.1','ports':ports})['scan_id']
            self.wait_scan()
        return sid

    def schedule(self, source, interval=15):
        sid=self.api('schedules',{'name':'Workshop','scan_id':source,'interval_minutes':interval})['id']
        return self.get_schedule(sid)

    def get_schedule(self, sid):
        return next(s for s in self.api('schedules')['schedules'] if s['id']==sid)

    def test_schedule_lifecycle_validation_conflicts_and_persistence(self):
        source=self.source();s=self.schedule(source)
        self.assertEqual(s['ports'],[22,23,443]);self.assertEqual(s['enabled'],1)
        self.assertEqual(len(self.api('scans')['scans']),1)
        self.assertIsNone(sg.schedule_tick())
        self.api('schedules',{'id':s['id'],'revision':s['revision'],'name':'Daily','interval_minutes':1440})
        with self.assertRaises(urllib.error.HTTPError) as caught:self.api('schedules/pause',s)
        self.assertEqual(caught.exception.code,409)
        s=self.get_schedule(s['id']);self.api('schedules/pause',s)
        sg.init_db();s=self.get_schedule(s['id']);self.assertEqual(s['enabled'],0)
        future=sg.monitoring.after(20000)
        self.assertIsNone(sg.schedule_tick(future))
        self.api('schedules/resume',s);s=self.get_schedule(s['id']);self.assertEqual(s['enabled'],1)
        self.api('schedules/delete',s);self.assertEqual(self.api('schedules')['schedules'],[])
        export=self.api('export');self.assertEqual(export['schedules'][0]['deleted'],1);self.assertEqual(len(export['scans']),1)
        for body in ({'name':'bad','scan_id':source,'interval_minutes':1},{'name':'bad','scan_id':source,'interval_minutes':True},{'name':'bad','scan_id':9999,'interval_minutes':15}):
            with self.assertRaises(urllib.error.HTTPError):self.api('schedules',body)

    def test_due_claim_no_overlap_no_catchup_and_restart(self):
        source=self.source('22');s=self.schedule(source)
        due=sg.monitoring.after(10080)
        with patch.object(sg,'launch_scan') as launch:
            sid=sg.schedule_tick(due)
            self.assertIsNotNone(sid);launch.assert_called_once()
            self.assertIsNone(sg.schedule_tick(due))
            with self.assertRaises(sg.monitoring.Conflict):sg.schedule_tick(requested=s['id'],revision=s['revision'])
        self.assertEqual(self.get_schedule(s['id'])['next_run'],sg.monitoring.after(15,due))
        sg.STATE['running']=False;sg.init_db()
        self.assertEqual(sg.latest()['status'],'interrupted')
        self.assertIsNone(sg.schedule_tick(due))
        with patch.object(sg,'probe',return_value={'outcome':'refused'}):
            nextid=sg.schedule_tick(sg.monitoring.after(16,due));self.wait_scan()
        self.assertEqual(sg.latest()['comparison_scan'],source)
        self.assertEqual(self.api('changes')['total'],1)
        self.assertEqual(len(self.api('scans')['scans']),3)

    def test_change_evidence_review_reopen_export_and_deduplication(self):
        source=self.source();s=self.schedule(source)
        def changed(host,port):
            if port==23:return {'outcome':'timeout'}
            return {'outcome':'open','service':'fixture','banner':'after <img src=x>',
                    'metadata':{'protocol':'vnc' if port==22 else 'https','identification':'verified','tls':{'sha256':'new'} if port==443 else {}}}
        with patch.object(sg,'probe',side_effect=changed):
            sid=self.api('schedules/run',s)['scan_id'];self.wait_scan()
            changes=self.api('changes')['changes']
            self.assertEqual({x['kind'] for x in changes},{'not_observed','protocol_changed','certificate_changed'})
            self.assertTrue(all(x['previous_scan']==source for x in changes))
            missing=next(x for x in changes if x['kind']=='not_observed')
            self.assertEqual(missing['evidence']['outcome'],'timeout');self.assertIsNone(missing['evidence']['after'])
            with sg.db() as c:sg.monitoring.record_changes(c,sid)
            self.assertEqual(self.api('changes')['total'],3)
            self.api('changes/review',{'ids':[x['id'] for x in changes],'reviewed':True})
            self.assertEqual(self.api('changes')['total'],0);sg.init_db()
            self.assertEqual(self.api('changes?state=reviewed')['total'],3)
            self.api('changes/review',{'ids':[missing['id']],'reviewed':False})
            self.assertEqual(self.api('changes')['total'],1)
            self.api('schedules/run',self.get_schedule(s['id']));self.wait_scan()
        self.assertEqual(sg.latest()['comparison_scan'],sid);self.assertEqual(sg.latest()['comparison_status'],'compared: 0 changes')
        self.assertEqual(len(self.api('export')['changes']),3)
        # Return of the missing service produces a new observation, not another missing alert.
        with patch.object(sg,'probe',return_value={'outcome':'open','service':'unknown','banner':'','metadata':{}}):
            self.api('schedules/run',self.get_schedule(s['id']));self.wait_scan()
        new=self.api('changes')['changes'][0];self.assertEqual(new['kind'],'new');self.assertEqual(new['port'],23)

    def test_scope_rechecked_and_paused_on_invalid_schedule(self):
        source=self.source();s=self.schedule(source);sg.CONFIG['allowed_cidrs']=['192.168.0.0/16']
        self.assertIsNone(sg.schedule_tick(sg.monitoring.after(20)))
        paused=self.get_schedule(s['id']);self.assertEqual(paused['enabled'],0);self.assertIn('outside',paused['last_error'])
        self.assertEqual(len(self.api('scans')['scans']),1)
        with self.assertRaises(urllib.error.HTTPError):self.api('schedules/resume',paused)
        self.assertEqual(self.get_schedule(s['id'])['enabled'],0)

    def test_cancelled_runs_do_not_report_missing_and_paused_run_stays_paused(self):
        source=self.source(','.join(map(str,range(20,60))));s=self.schedule(source)
        self.api('schedules/pause',s);s=self.get_schedule(s['id'])
        def slow(host,port):time.sleep(.1);return {'outcome':'refused'}
        with patch.object(sg,'probe',side_effect=slow):
            self.api('schedules/run',s);self.api('cancel',{});self.wait_scan()
        self.assertEqual(sg.latest()['status'],'cancelled')
        self.assertIn('skipped',sg.latest()['comparison_status'])
        self.assertEqual(self.api('changes')['total'],0);self.assertEqual(self.get_schedule(s['id'])['enabled'],0)

    def test_inbox_pagination_and_review_is_not_deletion(self):
        source=self.source(','.join(map(str,range(20,60))));s=self.schedule(source)
        with patch.object(sg,'probe',return_value={'outcome':'refused'}):
            self.api('schedules/run',s);self.wait_scan()
        first=self.api('changes');second=self.api('changes?offset=30')
        self.assertEqual(first['total'],40);self.assertEqual(len(first['changes']),30);self.assertEqual(len(second['changes']),10)
        self.assertFalse({x['id'] for x in first['changes']}&{x['id'] for x in second['changes']})
        self.api('changes/review',{'ids':[x['id'] for x in first['changes']],'reviewed':True})
        self.api('schedules/delete',self.get_schedule(s['id']))
        self.assertEqual(self.api('changes')['unreviewed'],10)
        self.assertEqual(self.api('changes?state=all')['total'],40)
