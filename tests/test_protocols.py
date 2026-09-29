import hashlib
import json
from pathlib import Path
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import protocols
import server


class Fixture(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True


class ProtocolTests(unittest.TestCase):
    def run_fixture(self,response,mode='http',tls_context=None):
        requests=[]
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                stream=self.request
                try:
                    stream.settimeout(3)
                    if tls_context: stream=tls_context.wrap_socket(stream,server_side=True)
                    if mode in ('http','https','rtsp'):requests.append(stream.recv(2048))
                    stream.sendall(response)
                except OSError: pass
                finally:stream.close()
        fixture=Fixture(('127.0.0.1',0),Handler)
        threading.Thread(target=fixture.serve_forever,daemon=True).start()
        port=fixture.server_address[1]
        self.addCleanup(fixture.server_close)
        self.addCleanup(fixture.shutdown)
        return port,requests

    def test_http_title_chunked_and_escaping(self):
        body=b'<html><title>Garage Camera &amp; Recorder</title><script>alert(1)</script></html>'
        response=b'HTTP/1.1 200 OK\r\nServer: LabCam\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n'+f'{len(body):x}\r\n'.encode()+body+b'\r\n0\r\n\r\n'
        port,requests=self.run_fixture(response)
        with patch.object(protocols,'HTTP_PORTS',{port}): result=protocols.inspect_service('127.0.0.1',port)
        self.assertEqual(result['metadata']['protocol'],'http')
        self.assertEqual(result['metadata']['http']['title'],'Garage Camera & Recorder')
        self.assertEqual(result['metadata']['device']['kind'],'camera')
        self.assertEqual(result['metadata']['identification'],'verified')
        self.assertIn(b'GET / HTTP/1.0',requests[0])

    def test_redirect_does_not_follow(self):
        port,requests=self.run_fixture(b'HTTP/1.1 302 Found\r\nLocation: http://example.invalid/private\r\nContent-Length: 0\r\n\r\n')
        with patch.object(protocols,'HTTP_PORTS',{port}): result=protocols.inspect_service('127.0.0.1',port)
        self.assertEqual(result['metadata']['http']['location'],'http://example.invalid/private')
        self.assertEqual(len(requests),1)

    def test_rtsp_authentication_response_and_no_camera_claim(self):
        port,requests=self.run_fixture(b'RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Basic realm="Media"\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n',mode='rtsp')
        with patch.object(protocols,'RTSP_PORTS',{port}): result=protocols.inspect_service('127.0.0.1',port)
        self.assertEqual(result['metadata']['protocol'],'rtsp')
        self.assertEqual(result['metadata']['rtsp']['status'],401)
        self.assertEqual(result['metadata']['device']['kind'],'streaming')
        self.assertEqual(requests[0].split(b'\r\n')[0],b'OPTIONS * RTSP/1.0')
        self.assertNotIn(b'Authorization:',requests[0])

    def test_https_self_signed_certificate(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert=Path(tmp)/'cert.pem';key=Path(tmp)/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=scopeglass.test','-addext','subjectAltName=DNS:scopeglass.test,IP:127.0.0.1'],check=True,capture_output=True,timeout=15)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
            port,requests=self.run_fixture(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 22\r\n\r\n<title>Secure</title>  ',mode='https',tls_context=context)
            with patch.object(protocols,'HTTPS_PORTS',{port}),patch.object(protocols,'TLS_PORTS',{port}):
                result=protocols.inspect_service('127.0.0.1',port)
            m=result['metadata']
            self.assertEqual(m['protocol'],'https')
            self.assertEqual(m['http']['title'],'Secure')
            self.assertTrue(m['tls']['version'].startswith('TLS'))
            self.assertEqual(m['tls']['sha256'],hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest())
            self.assertIn('scopeglass.test',m['tls']['subject'])
            self.assertIn('Not evaluated',m['tls']['trust'])

    def test_protocol_contradicts_port_hint(self):
        for raw,port,category in [(b'HTTP/1.0 200 OK\r\n\r\n',23,'Possible Telnet'),(b'SSH-2.0-fixture\r\n',554,'Possible camera interface')]:
            meta=protocols.parse_response(raw)
            findings=server.classify({'port':port,'banner':raw.decode(),'metadata':meta})
            self.assertFalse(any(f['category']==category for f in findings))
        self.assertEqual(protocols.parse_response(b'login:')['identification'],'port_hint')
        self.assertEqual(protocols.parse_response(b'\xff\xfb\x01login:')['protocol'],'telnet')

    def test_response_read_is_capped_and_malformed_stays_unknown(self):
        response=b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 999999\r\n\r\n'+b'x'*40000
        port,_=self.run_fixture(response)
        with patch.object(protocols,'HTTP_PORTS',{port}):result=protocols.inspect_service('127.0.0.1',port)
        self.assertTrue(result['metadata']['response_limited'])
        self.assertLessEqual(len(result['banner']),500)
        self.assertEqual(protocols.parse_response(b'RTSP nonsense')['protocol'],'unknown')

    def test_bad_tls_preserves_open_port(self):
        port,_=self.run_fixture(b'not a TLS service',mode='banner')
        with patch.object(protocols,'TLS_PORTS',{port}):result=protocols.inspect_service('127.0.0.1',port)
        self.assertEqual(result['outcome'],'open')
        self.assertEqual(result['metadata']['protocol'],'unknown')
        self.assertIn('probe_note',result['metadata'])


if __name__=='__main__':unittest.main()
