"""Restore, cleanup, snapshots, and stale-client regression coverage."""
from contextlib import contextmanager
from copy import deepcopy
import datetime as dt
import json
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
import test_server as base
import dataops
sg=base.sg


class DataTests(unittest.TestCase):
    setUp=base.ServerTests.setUp
    tearDown=base.ServerTests.tearDown
    api=base.ServerTests.api
    wait_scan=base.ServerTests.wait_scan

    def scan(self,ports='22,23',refused=False):
        response={'outcome':'refused'} if refused else {'outcome':'open','service':'fixture','banner':'<script>fixture</script>','metadata':{'protocol':'telnet','identification':'verified'}}
        with patch.object(sg,'probe',return_value=response):
            sid=self.api('scan',{'targets':'127.0.0.1','ports':ports})['scan_id'];self.wait_scan()
        return sid

    def populated(self):
        sid=self.scan()
        self.api('baselines',{'scan_id':sid,'note':'Before'})
        asset=self.api(f'device?host=127.0.0.1&scan={sid}')['asset']
        self.api('device',{**asset,'name':'Garage','notes':'Review','tags':['lab'],'expected_ports':[23]})
        self.api('views',{'name':'Pinned','settings':{'scan':str(sid),'q':'port:23','category':'all','view':'devices','sort':'ip'}})
        schedule=self.api('schedules',{'name':'Daily','scan_id':sid,'interval_minutes':1440})['id']
        settings=self.api('schedules')['schedules'][0]
        with patch.object(sg,'probe',return_value={'outcome':'refused'}):
            self.api('schedules/run',settings);self.wait_scan()
        changes=self.api('changes')['changes']
        self.api('changes/review',{'ids':[c['id'] for c in changes],'reviewed':True})
        return self.api('export')

    def apply(self,body,preview=None,confirmation=None):
        preview=preview or self.api('data/preview',body)
        return self.api('data/apply',{**body,'token':preview['token'],'scan_ids':preview['scan_ids'],'confirmation':confirmation or {'restore':'RESTORE','cleanup':'DELETE OLD SCANS','fresh':'FRESH START'}[body['action']]})

    def rejects(self,path,body,status=400):
        with self.assertRaises(urllib.error.HTTPError) as caught:self.api(path,body)
        self.assertEqual(caught.exception.code,status)
        return json.load(caught.exception)['error']

    def test_roundtrip_all_tables_backup_and_paused_schedules(self):
        original=self.populated();epoch=sg.current_epoch();body={'action':'restore','archive':original}
        preview=self.api('data/preview',body)
        self.assertEqual(preview['counts'],{k:len(original[k]) for k in dataops.TABLES})
        self.assertTrue(preview['warnings']);self.assertEqual(sg.current_epoch(),epoch)
        self.assertEqual(dataops.snapshot_hash(self.api('export')),dataops.snapshot_hash(original))
        result=self.apply(body,preview);backup=Path(result['backup']);self.assertTrue(backup.is_file())
        self.assertEqual(list(backup.parent.iterdir()),[backup])
        with sqlite3.connect(backup) as c:
            self.assertEqual(c.execute('PRAGMA quick_check').fetchone()[0],'ok')
            self.assertEqual(c.execute('SELECT enabled FROM schedules').fetchone()[0],1)
            self.assertEqual(c.execute("SELECT value FROM app_meta WHERE key='epoch'").fetchone()[0],epoch)
        self.assertNotEqual(sg.current_epoch(),epoch)
        restored=self.api('export')
        for table in dataops.TABLES:
            if table not in ('schedules','scans','observations'):self.assertEqual(restored[table],original[table])
            self.assertEqual(len(restored[table]),len(original[table]))
        self.assertEqual(restored['schedules'][0]['enabled'],0)
        self.assertIsNone(sg.schedule_tick(sg.monitoring.after(20000)))
        self.assertFalse(sg.STATE['running'])
        self.assertEqual(self.api('changes?state=reviewed')['total'],2)
        self.assertEqual(self.api('observations?scan=1')['matching'],2)

    def test_invalid_archives_leave_database_untouched(self):
        archive=self.populated();before=dataops.snapshot_hash(archive)
        def case(change):
            bad=deepcopy(archive);change(bad);return bad
        invalid=[case(lambda a:a.update(schema='wrong')),case(lambda a:a.update(version='9.0.0')),case(lambda a:a['scans'][0].update(checked=0)),case(lambda a:a['observations'][0].update(host='127.0.0.2')),case(lambda a:a['observations'].append(a['observations'][0])),case(lambda a:a['baselines'][0].update(scan_id=999)),case(lambda a:a['saved_views'][0]['settings'].update(scan='999')),case(lambda a:a['schedules'][0].update(last_scan=1)),case(lambda a:a['observations'][0].update(metadata={'identification':'verified'})),case(lambda a:a['observations'][0].update(metadata={'tls':{'names':'bad'}})),case(lambda a:a['observations'][0].update(metadata={'http':{'title':[]}})),case(lambda a:a['scans'][0].update(started='yesterday')),case(lambda a:a['scans'][0].update(parent_scan=2)),case(lambda a:a['changes'][0]['evidence'].update(after={})),case(lambda a:a['changes'][0]['evidence'].update(outcome='open')),case(lambda a:a['changes'][0]['evidence']['before'].update(banner='invented')),case(lambda a:a['checks'].pop()),case(lambda a:a['assets'][0].update(revision=True))]
        for bad in invalid:
            with self.subTest(archive=bad):self.rejects('data/preview',{'action':'restore','archive':bad})
        with patch.object(dataops,'MAX_ARCHIVE',10):
            with self.assertRaises(ValueError):dataops.validate_archive(archive,sg.PRESETS)
        self.assertEqual(dataops.snapshot_hash(self.api('export')),before)
        self.assertFalse((Path(sg.DB).parent/'backups').exists())

    def test_confirmation_and_preview_binding_expiry_and_stale_data(self):
        self.scan();body={'action':'fresh'};preview=self.api('data/preview',body)
        self.rejects('data/apply',{**body,'token':preview['token'],'confirmation':'yes'})
        self.rejects('data/apply',{'action':'restore','archive':self.api('export'),'token':preview['token'],'confirmation':'RESTORE'},409)
        with patch.object(dataops.time,'time',return_value=9999999999):
            self.rejects('data/apply',{**body,'token':preview['token'],'confirmation':'FRESH START'},409)
        self.api('baselines',{'scan_id':1})
        self.rejects('data/apply',{**body,'token':preview['token'],'confirmation':'FRESH START'},409)
        restore={'action':'restore','archive':self.api('export')};preview=self.api('data/preview',restore)
        restore['archive']['baselines'][0]['note']='tampered'
        self.rejects('data/apply',{**restore,'token':preview['token'],'confirmation':'RESTORE'},409)
        self.assertEqual(self.api('data/status')['counts']['scans'],1)

    def test_backup_failure_and_insert_failure_roll_back(self):
        archive=self.populated();before=dataops.snapshot_hash(archive);epoch=sg.current_epoch();body={'action':'fresh'};preview=self.api('data/preview',body)
        with patch.object(dataops,'safety_backup',side_effect=OSError('disk full')):
            self.rejects('data/apply',{**body,'token':preview['token'],'confirmation':'FRESH START'},500)
        def failure(c,data):c.execute('DELETE FROM scans');raise sqlite3.IntegrityError('fixture rollback')
        with patch.object(dataops,'replace_data',side_effect=failure):
            self.rejects('data/apply',{**body,'token':preview['token'],'confirmation':'FRESH START'},500)
        self.assertEqual(dataops.snapshot_hash(self.api('export')),before);self.assertEqual(sg.current_epoch(),epoch)

    def test_fresh_start_and_epoch_reject_old_client_even_when_ids_reused(self):
        archive=self.populated();old=sg.current_epoch();config=deepcopy(sg.CONFIG)
        self.apply({'action':'fresh'})
        self.assertTrue(all(n==0 for n in self.api('data/status')['counts'].values()))
        self.assertEqual(sg.CONFIG,config)
        self.apply({'action':'restore','archive':archive})
        request=urllib.request.Request(self.url+'device',data=json.dumps({**archive['assets'][0],'name':'Stale edit'}).encode(),headers={'Content-Type':'application/json','X-Scopeglass-Epoch':old})
        with self.assertRaises(urllib.error.HTTPError) as caught:urllib.request.urlopen(request,timeout=5)
        self.assertEqual(caught.exception.code,409)
        self.assertEqual(self.api('export')['assets'][0]['name'],'Garage')
        self.assertEqual(len(list((Path(sg.DB).parent/'backups').glob('*.sqlite3'))),2)

    def test_cleanup_protects_references_and_removes_only_unneeded_old_scans(self):
        archive=self.populated();removable=self.scan();parent=self.scan();latest=self.scan()
        with sg.db() as c:
            c.execute("UPDATE scans SET started='2001-01-01T00:00:00+00:00'")
            c.execute('UPDATE scans SET parent_scan=? WHERE id=?',(parent,latest))
        before=self.api('export');body={'action':'cleanup','days':90};preview=self.api('data/preview',body)
        self.assertEqual(preview['scan_ids'],[removable]);self.assertEqual(preview['protected'],4)
        self.assertEqual(preview['counts'],{'scans':1,'observations':2,'checks':2})
        self.rejects('data/apply',{**body,'token':preview['token'],'confirmation':'DELETE OLD SCANS','scan_ids':[1]},409)
        epoch=sg.current_epoch();self.apply(body,preview)
        after=self.api('export');self.assertEqual(sg.current_epoch(),epoch)
        self.assertNotIn(removable,{r['id'] for r in after['scans']})
        self.assertFalse(any(r['scan_id']==removable for r in after['checks']+after['observations']))
        for table in ('assets','baselines','saved_views','schedules','changes'):self.assertEqual(before[table],after[table])
        dataops.validate_archive(after,sg.PRESETS)

    def test_partial_restore_legacy_tables_and_current_allowlist(self):
        sid=self.scan();archive=self.api('export');archive['version']='0.3.0';archive['scans'][0].update(status='running',finished=None)
        for key in ('assets','saved_views','schedules','changes'):del archive[key]
        sg.CONFIG['allowed_cidrs']=['192.168.0.0/16']
        self.apply({'action':'restore','archive':archive})
        self.assertEqual(self.api('observations')['scan']['status'],'interrupted')
        self.assertFalse(sg.STATE['running'])
        self.rejects('scan',{'targets':'127.0.0.1','ports':'22'})

    def test_active_scan_blocks_maintenance(self):
        sg.STATE['running']=True
        try:self.rejects('data/preview',{'action':'fresh'},409)
        finally:sg.STATE['running']=False
        self.assertEqual(self.api('data/status')['counts']['scans'],0)

    def test_report_includes_full_filtered_snapshot(self):
        # 128 rows exceed the normal 100-service page size.
        sid=self.scan(','.join(map(str,range(1000,1128))))
        self.assertEqual(len(self.api('observations')['observations']),100)
        all_rows=self.api('report?scan='+str(sid));self.assertEqual(len(all_rows['observations']),128)
        filtered=self.api('report?q=port%3A1010-1115&sort=port');self.assertEqual(filtered['matching'],106);self.assertEqual(len(filtered['observations']),106)
        original=sg.db;changed=[]
        def update(sql):
            if sql.startswith('SELECT host,port') and not changed:
                changed.append(True)
                with sqlite3.connect(sg.DB) as c:
                    c.execute('DELETE FROM observations WHERE port=1000')
                    c.execute("UPDATE scans SET status='cancelled',checked=127")
        @contextmanager
        def traced():
            with original() as c:c.set_trace_callback(update);yield c
        with patch.object(sg,'db',traced):snapshot=self.api('report')
        self.assertEqual(snapshot['scan']['checked'],128);self.assertEqual(len(snapshot['observations']),128)
        self.assertEqual(len(self.api('report')['observations']),127)
