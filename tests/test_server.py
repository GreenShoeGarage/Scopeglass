import importlib.util
import sys
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

spec = importlib.util.spec_from_file_location('scopeglass', Path(__file__).resolve().parents[1]/'server.py')
sg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sg)


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        sg.DB = str(Path(self.tmp.name)/'test.db')
        sg.CONFIG = {'allowed_cidrs':['127.0.0.0/8','192.168.0.0/16']}
        sg.CANCEL.clear()
        sg.STATE.update(running=False,completed=0,total=0,error='',scan_id=None,cancelling=False)
        sg.init_db()
        self.http = sg.ThreadingHTTPServer(('127.0.0.1',0),sg.Handler)
        threading.Thread(target=self.http.serve_forever,daemon=True).start()
        self.url = f'http://127.0.0.1:{self.http.server_port}/api/'

    def tearDown(self):
        sg.CANCEL.set()
        self.wait_scan()
        self.http.shutdown()
        self.http.server_close()
        self.tmp.cleanup()

    def api(self,path,data=None):
        body = None if data is None else json.dumps(data).encode()
        request = urllib.request.Request(self.url+path,data=body,headers={'Content-Type':'application/json','X-Scopeglass-Epoch':sg.current_epoch()})
        with urllib.request.urlopen(request,timeout=5) as response:
            return json.load(response)

    def wait_scan(self):
        for _ in range(150):
            if not sg.STATE['running']:
                return
            time.sleep(.02)
        self.fail('Scan did not finish')

    def test_scope_and_preview(self):
        self.assertEqual(sg.addresses('127.0.0.1,127.0.0.1'),['127.0.0.1'])
        self.assertEqual(sg.ports_from('80,81-83'),[80,81,82,83])
        for target in ['8.8.8.8','0.0.0.0/0','192.168.0.0/16','::1']:
            with self.assertRaises(ValueError): sg.addresses(target)
        plan = self.api('preview',{'targets':'127.0.0.1','preset':'telnet'})
        self.assertEqual(plan['ports'],[23,2323])
        self.assertEqual(plan['total'],2)
        self.assertEqual(self.api('scans')['scans'],[])
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.api('scan',{'targets':'127.0.0.1','preset':'typo'})
        self.assertEqual(caught.exception.code,400)

    def test_real_open_service_and_baseline(self):
        result=self.api('scan',{'targets':'127.0.0.1','ports':str(self.http.server_port)})
        self.wait_scan()
        data=self.api('observations')
        self.assertEqual(data['scan']['status'],'complete')
        self.assertEqual(data['scan']['checked'],1)
        self.assertEqual(data['scan']['outcomes'],{'open':1})
        self.assertEqual(data['observations'][0]['port'],self.http.server_port)
        self.api('baselines',{'scan_id':result['scan_id']})
        baseline=self.api('baselines')['baselines'][0]['id']
        self.assertEqual(self.api(f'compare?baseline={baseline}')['missing'],[])
        self.assertEqual(len(self.api('export')['checks']),1)

    def test_cancellation_is_bounded_and_persisted(self):
        def slow_probe(host,port):
            time.sleep(.10)
            return {'outcome':'open','service':'fixture','banner':'test'}
        with patch.object(sg,'probe',side_effect=slow_probe):
            self.api('scan',{'targets':'127.0.0.0/24','preset':'overview'})
            self.api('cancel',{})
            self.wait_scan()
        result=self.api('observations')
        self.assertEqual(result['scan']['status'],'cancelled')
        self.assertLessEqual(result['scan']['checked'],16)
        self.assertLess(result['scan']['checked'],result['scan']['total'])
        self.assertEqual(result['open_total'],result['scan']['checked'])
        with self.assertRaises(urllib.error.HTTPError):
            self.api('baselines',{'scan_id':result['scan_id']})

    def test_restart_recovery_and_old_database_migration(self):
        with sg.db() as c:
            c.execute("INSERT INTO scans(started,status,targets,ports,checked,total) VALUES(?,'running',?,?,1,2)",
                      (sg.now(),'["127.0.0.1"]','[23,2323]'))
        sg.init_db()
        recovered=self.api('observations')['scan']
        self.assertEqual(recovered['status'],'interrupted')
        self.assertEqual(recovered['checked'],1)
        # A genuine v0.2 schema gains fields without losing rows.
        old=Path(self.tmp.name)/'old.db'
        with sqlite3.connect(old) as c:
            c.execute('CREATE TABLE scans(id INTEGER PRIMARY KEY,started TEXT,finished TEXT,status TEXT,targets TEXT,ports TEXT,error TEXT)')
            c.execute("INSERT INTO scans VALUES(1,'today',NULL,'complete','[\"127.0.0.1\"]','[22,80]', '')")
        sg.DB=str(old);sg.init_db()
        self.assertEqual(sg.latest()['total'],2)
        self.assertEqual(sg.latest()['checked'],2)

    def test_network_detection_and_partial_network_label(self):
        fixture=[{'ifname':'eth0','addr_info':[{'family':'inet','local':'192.168.4.20','prefixlen':16}]}]
        with patch.object(sg.platform,'system',return_value='Linux'),patch.object(sg.subprocess,'run') as run:
            run.return_value.stdout=json.dumps(fixture)
            data=sg.local_networks()['networks'][0]
        self.assertTrue(data['partial'])
        self.assertEqual(data['network'],'192.168.0.0/16')
        self.assertEqual(data['target'],'192.168.4.0/24')
        self.assertEqual(data['hosts'],254)
        with patch.object(sg.platform,'system',return_value='Darwin'),patch.object(sg.subprocess,'run') as run:
            run.return_value.stdout='en0: flags=UP\n\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255\n'
            self.assertEqual(sg.local_networks()['networks'][0]['target'],'192.168.1.0/24')
        with patch.object(sg.platform,'system',return_value='Windows'),patch.object(sg.subprocess,'run') as run:
            run.return_value.stdout=json.dumps({'InterfaceAlias':'Wi-Fi','IPAddress':'192.168.2.10','PrefixLength':24})
            self.assertEqual(sg.local_networks()['networks'][0]['target'],'192.168.2.0/24')

    def test_pagination_filters_and_scope_comparison(self):
        with sg.db() as c:
            c.execute("INSERT INTO scans(started,status,targets,ports,total,checked) VALUES(?,'complete',?,?,260,260)",(sg.now(),'["127.0.0.1"]','[23,80]'))
            sid=c.execute('SELECT max(id) FROM scans').fetchone()[0]
            for i in range(260):
                c.execute('INSERT INTO observations(scan_id,host,port,service,banner,observed) VALUES(?,?,?,?,?,?)',(sid,f'127.0.0.{i//2+1}',23 if i%2 else 80,'fixture','',sg.now()))
        data=self.api('observations?category=telnet&offset=100&limit=100')
        self.assertEqual(data['matching'],130)
        self.assertEqual(len(data['observations']),30)
        device_page=self.api('observations?view=devices&limit=1')
        self.assertEqual(device_page['page_total'],130)
        self.assertEqual(len(device_page['observations']),2)
        self.assertEqual(len({x['host'] for x in device_page['observations']}),1)
        self.api('baselines',{'scan_id':sid})
        baseline=self.api('baselines')['baselines'][0]['id']
        with sg.db() as c:
            c.execute("INSERT INTO scans(started,status,targets,ports,total,checked) VALUES(?,'complete',?,?,1,1)",(sg.now(),'["127.0.0.2"]','[80]'))
        with self.assertRaises(urllib.error.HTTPError) as caught:self.api(f'compare?baseline={baseline}')
        self.assertEqual(caught.exception.code,409)

    def test_annotations_conflicts_and_expected_service(self):
        with patch.object(sg,'probe',return_value={'outcome':'open','service':'telnet','banner':'login:'}):
            started=self.api('scan',{'targets':'127.0.0.1','ports':'23'})
            self.wait_scan()
        original=self.api('observations')['observations'][0]
        record=self.api(f"device?host=127.0.0.1&scan={started['scan_id']}")
        self.assertTrue(record['services'][0]['findings'][0]['next_step'])
        payload={**record['asset'],'name':'Garage camera','tags':['garage','camera'],'notes':'Owner: test','expected_ports':[23]}
        saved=self.api('device',payload)['asset']
        self.assertEqual(saved['revision'],1)
        with self.assertRaises(urllib.error.HTTPError) as caught:self.api('device',payload)
        self.assertEqual(caught.exception.code,409)
        annotated=self.api('observations?q=garage')
        self.assertEqual(annotated['matching'],1)
        self.assertTrue(annotated['observations'][0]['expected'])
        self.assertEqual(annotated['observations'][0]['findings'][0]['severity'],original['findings'][0]['severity'])
        sg.init_db()
        self.assertEqual(self.api(f"device?host=127.0.0.1&scan={started['scan_id']}")['asset']['notes'],'Owner: test')
        self.assertEqual(self.api('export')['assets'][0]['expected_ports'],[23])
        with self.assertRaises(urllib.error.HTTPError):self.api('device',{**saved,'expected_ports':[True]})

    def test_focused_rescan_tracks_changes_and_enforces_scope(self):
        with patch.object(sg,'probe',return_value={'outcome':'open','service':'fixture','banner':''}):
            started=self.api('scan',{'targets':'127.0.0.1','ports':'23,80'})
            self.wait_scan()
        with patch.object(sg,'probe',return_value={'outcome':'refused'}):
            rescanned=self.api('rescan',{'host':'127.0.0.1','scan_id':started['scan_id'],'port':23})
            self.wait_scan()
        result=self.api('observations')
        self.assertEqual(result['scan']['ports'],[23])
        self.assertEqual(result['scan']['parent_scan'],started['scan_id'])
        self.assertEqual(result['rescan_comparison']['not_observed'],[{'host':'127.0.0.1','port':23}])
        self.assertEqual(self.api(f"observations?scan={started['scan_id']}")['open_total'],2)
        for payload in [{'host':'127.0.0.2','scan_id':started['scan_id']}, {'host':'127.0.0.1','scan_id':started['scan_id'],'port':22}]:
            with self.assertRaises(urllib.error.HTTPError):self.api('rescan',payload)
        sg.CONFIG={'allowed_cidrs':['192.168.0.0/16']}
        with self.assertRaises(urllib.error.HTTPError):self.api('rescan',{'host':'127.0.0.1','scan_id':started['scan_id']})

    def test_saved_views_update_conflict_delete_and_export(self):
        settings={'q':'port:23 expected:false','category':'all','sort':'severity','view':'devices','scan':'latest'}
        created=self.api('views',{'name':'Telnet review','settings':settings})
        view=self.api('views')['views'][0]
        self.assertEqual(view['id'],created['id'])
        self.assertEqual(view['settings'],settings)
        changed={**view,'settings':{**settings,'q':'verified:true'}}
        self.api('views',changed)
        with self.assertRaises(urllib.error.HTTPError) as caught:self.api('views',changed)
        self.assertEqual(caught.exception.code,409)
        self.assertEqual(self.api('export')['saved_views'][0]['settings']['q'],'verified:true')
        sg.init_db()
        current=self.api('views')['views'][0]
        self.api('views/delete',{'id':current['id'],'revision':current['revision']})
        self.assertEqual(self.api('views')['views'],[])
        with self.assertRaises(urllib.error.HTTPError):self.api('views',{'name':'Bad','settings':{**settings,'q':'port:99999'}})
        self.assertFalse(sg.STATE['running'])

    def test_api_errors_and_classification_limits(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:self.api('observations?scan=bad')
        self.assertEqual(caught.exception.code,400)
        self.assertFalse(any(f['category']=='Possible camera interface' for f in sg.classify({'port':80,'banner':'HTTP/1.1 200 OK'})))
        self.assertEqual(sg.classify({'port':554,'banner':''})[0]['confidence'],'low')


if __name__=='__main__': unittest.main()
