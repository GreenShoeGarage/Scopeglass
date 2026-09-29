import datetime as dt
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from searching import parse_query,matches,sort_items

class SearchTests(unittest.TestCase):
    def setUp(self):
        self.clock=dt.datetime(2026,9,26,tzinfo=dt.timezone.utc)
        self.asset={'name':'Garage Camera','tags':['Garage','Camera'],'notes':'Owner: workshop','expected_ports':[]}
        self.item={'host':'192.168.1.10','port':23,'service':'telnet','banner':'Hello','observed':'2026-09-18T00:00:00+00:00','expected':False,'metadata':{'protocol':'telnet','identification':'verified'},'findings':[{'severity':'high'}]}
    def test_combined_filters_negation_quotes_and_age(self):
        q='net:192.168.1.0/24 port:20-25 tag:garage name:"Garage Camera" expected:false verified:true severity:high age:>7d -tag:office'
        self.assertTrue(matches(self.item,self.asset,parse_query(q),self.clock))
        self.assertFalse(matches(self.item,self.asset,parse_query('age:<7d'),self.clock))
        self.assertFalse(matches(self.item,self.asset,parse_query('port:80'),self.clock))
        self.assertTrue(matches(self.item,self.asset,parse_query('garage workshop'),self.clock))
    def test_errors_and_unknown_protocol(self):
        for q in ['typo:value','port:99999','port:100-2','expected:yes','age:7d','tag:"unclosed','ip:not-an-ip','type:router']:
            with self.assertRaises(ValueError,msg=q):parse_query(q)
        unverified={**self.item,'metadata':{}}
        self.assertFalse(matches(unverified,self.asset,parse_query('protocol:telnet'),self.clock))
        self.assertTrue(matches(unverified,self.asset,parse_query('service:telnet verified:false'),self.clock))
        self.assertFalse(matches(self.item,self.asset,parse_query('type:camera'),self.clock))
        self.assertTrue(matches(self.item,self.asset,parse_query('type:unknown'),self.clock))
    def test_numeric_ip_and_port_sorting(self):
        items=[self.item,{**self.item,'host':'192.168.1.2','port':443}]
        assets={r['host']:self.asset for r in items}
        self.assertEqual(sort_items(items,assets,'ip')[0]['host'],'192.168.1.2')
        self.assertEqual(sort_items(items,assets,'port')[0]['port'],23)
        with self.assertRaises(ValueError):sort_items(items,assets,'bogus')

if __name__=='__main__':unittest.main()
