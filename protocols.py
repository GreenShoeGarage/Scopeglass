"""Bounded protocol observations. No authentication, redirects, or media playback."""
import hashlib
from html.parser import HTMLParser
import re
import socket
import ssl
import tempfile
import time

HTTP_PORTS = {80,81,3000,8000,8001,8080,8081,9000,9090,8899}
HTTPS_PORTS = {443,8443}
TLS_PORTS = HTTPS_PORTS | {465,993,995}
RTSP_PORTS = {554,8554}
MAX_RESPONSE = 16384
RESPONSE_SECONDS = 1.2
CAMERA_TERMS = re.compile(r'\b(camera|webcam|ipcam|onvif|dvr|nvr|hikvision|dahua|axis communications)\b', re.I)


def clean(value, limit=300):
    return ' '.join(''.join(c if c.isprintable() else ' ' for c in str(value)).split())[:limit]


class TitleParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.inside = False
        self.parts = []
    def handle_starttag(self, tag, attrs):
        if tag == 'title': self.inside = True
    def handle_endtag(self, tag):
        if tag == 'title': self.inside = False
    def handle_data(self, data):
        if self.inside: self.parts.append(data)


def unchunk(body):
    output = bytearray()
    while body:
        end = body.find(b'\r\n')
        if end < 0: break
        try: size = int(body[:end].split(b';', 1)[0],16)
        except ValueError: break
        if size <= 0: break
        body = body[end+2:]
        output.extend(body[:size])
        if len(body) < size+2: break
        body = body[size+2:]
    return bytes(output)


def parse_response(raw, encrypted=False):
    metadata = {'protocol':'unknown','identification':'port_hint','evidence':[]}
    first = raw.split(b'\r\n',1)[0].decode('latin1',errors='replace')
    match = re.match(r'^(HTTP|RTSP)/(\d\.\d) ([1-5]\d\d)(?: |$)',first)
    if match:
        protocol = 'https' if match[1]=='HTTP' and encrypted else match[1].lower()
        metadata.update(protocol=protocol,identification='verified',evidence=[clean(first)])
        header, _, body = raw.partition(b'\r\n\r\n')
        headers = {}
        for line in header.split(b'\r\n')[1:]:
            if b':' in line:
                key,value = line.split(b':',1)
                headers[key.decode('latin1').lower()] = clean(value.decode('latin1'))
        info = {'status':int(match[3]),'version':match[2]}
        for name in ('server','content-type','location','www-authenticate','public','allow'):
            if name in headers: info[name.replace('-','_')] = headers[name]
        if match[1]=='HTTP':
            if headers.get('transfer-encoding','').lower()=='chunked': body=unchunk(body)
            if not headers.get('content-encoding') and ('html' in headers.get('content-type','').lower() or b'<title' in body.lower()):
                parser = TitleParser()
                parser.feed(body.decode('utf-8',errors='replace'))
                title = clean(' '.join(parser.parts))
                if title: info['title']=title
            metadata['http']=info
        else:
            metadata['rtsp']=info
    elif re.match(rb'^SSH-\d\.\d-',raw):
        metadata.update(protocol='ssh',identification='verified',evidence=[clean(first)])
    elif re.match(rb'^RFB \d{3}\.\d{3}\n',raw):
        metadata.update(protocol='vnc',identification='verified',evidence=[clean(first)])
    elif any(raw[i]==255 and raw[i+1] in (251,252,253,254) for i in range(max(0,len(raw)-2))):
        metadata.update(protocol='telnet',identification='verified',evidence=['Observed Telnet IAC option negotiation bytes.'])
    elif re.match(rb'^220[ -]',raw):
        # A numeric greeting alone cannot distinguish SMTP and FTP.
        if re.search(rb'\b(?:ESMTP|SMTP)\b',raw[:300],re.I):
            metadata.update(protocol='smtp',identification='verified',evidence=[clean(first)])
        elif re.search(rb'\bFTP\b',raw[:300],re.I):
            metadata.update(protocol='ftp',identification='verified',evidence=[clean(first)])
    advertised = ' '.join(str(v) for section in ('http','rtsp') for v in metadata.get(section,{}).values())
    hint = CAMERA_TERMS.search(advertised)
    if hint:
        metadata['device']={'kind':'camera','label':'Likely camera / video device','confidence':'medium',
                            'evidence':f'Service metadata advertises “{clean(hint[0])}”; device identity is not independently verified.'}
    elif metadata['protocol']=='rtsp':
        metadata['device']={'kind':'streaming','label':'Streaming service; device type unknown','confidence':'low',
                            'evidence':'An RTSP response verifies a streaming control service, not a physical camera.'}
    return metadata


def read_bounded(stream, want_body):
    chunks = bytearray()
    deadline = time.monotonic()+RESPONSE_SECONDS
    truncated = False
    while len(chunks) < MAX_RESPONSE:
        remaining = deadline-time.monotonic()
        if remaining <= 0: break
        stream.settimeout(remaining)
        try: block=stream.recv(min(4096,MAX_RESPONSE-len(chunks)))
        except (OSError,TimeoutError): break
        if not block: break
        chunks.extend(block)
        if b'\r\n\r\n' in chunks:
            if not want_body: break
            headers,_,body=chunks.partition(b'\r\n\r\n')
            length=re.search(rb'(?im)^content-length:\s*(\d+)',headers)
            if length and len(body)>=int(length[1]): break
            if b'</title>' in body.lower(): break
        elif not want_body and (b'\n' in chunks or (len(chunks)>=3 and chunks[0]==255 and chunks[1] in (251,252,253,254))):
            break
    truncated=len(chunks)>=MAX_RESPONSE
    return bytes(chunks),truncated


def certificate_metadata(stream):
    cipher=stream.cipher()
    result={'version':stream.version(),'cipher':cipher[0] if cipher else '',
            'trust':'Not evaluated — inspection accepts self-signed and untrusted certificates.'}
    der=stream.getpeercert(binary_form=True)
    if not der: return result
    result['sha256']=hashlib.sha256(der).hexdigest()
    # CPython's bundled decoder is optional; fingerprint/version remain available elsewhere.
    decoder=getattr(getattr(ssl,'_ssl',None),'_test_decode_cert',None)
    if decoder:
        try:
            with tempfile.TemporaryDirectory(prefix='scopeglass-cert-') as folder:
                from pathlib import Path
                file=Path(folder)/'peer.pem'
                file.write_text(ssl.DER_cert_to_PEM_cert(der))
                cert=decoder(str(file))
            for key in ('subject','issuer'):
                result[key]=clean(', '.join(f'{k}={v}' for group in cert.get(key,()) for k,v in group),500)
            result['not_before']=cert.get('notBefore','')
            result['not_after']=cert.get('notAfter','')
            result['names']=[clean(f'{k}: {v}') for k,v in cert.get('subjectAltName',())][:20]
        except (OSError,ValueError,ssl.SSLError):
            result['details_note']='Certificate fields could not be decoded.'
    else:
        result['details_note']='Certificate field decoding is unavailable in this Python runtime.'
    return result


def inspect_service(host,port):
    try:
        stream=socket.create_connection((host,port),timeout=.65)
    except ConnectionRefusedError: return {'outcome':'refused'}
    except (socket.timeout,TimeoutError): return {'outcome':'timeout'}
    except OSError: return {'outcome':'unreachable'}
    metadata={'protocol':'unknown','identification':'port_hint','evidence':[]}
    raw=b''
    try:
        stream.settimeout(RESPONSE_SECONDS)
        if port in TLS_PORTS:
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname=False
            context.verify_mode=ssl.CERT_NONE
            stream=context.wrap_socket(stream,server_hostname=host)
            metadata['tls']=certificate_metadata(stream)
            metadata.update(protocol='tls',identification='verified',evidence=['TLS handshake completed.'])
        if port in HTTP_PORTS|HTTPS_PORTS:
            stream.sendall(f'GET / HTTP/1.0\r\nHost: {host}:{port}\r\nUser-Agent: Scopeglass/0.4\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n'.encode())
            raw,truncated=read_bounded(stream,True)
        elif port in RTSP_PORTS:
            stream.sendall(b'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Scopeglass/0.4\r\n\r\n')
            raw,truncated=read_bounded(stream,False)
        else:
            raw,truncated=read_bounded(stream,False)
        identified=parse_response(raw,encrypted=bool(metadata.get('tls')))
        if identified['protocol']!='unknown': metadata.update(identified)
        metadata['response_limited']=truncated
    except (OSError,ValueError) as error:
        metadata['probe_note']=clean(str(error)) or 'Protocol response could not be read.'
    finally:
        stream.close()
    try: service=socket.getservbyport(port,'tcp')
    except OSError: service='tcp'
    return {'outcome':'open','service':service,'banner':clean(raw.decode('utf-8',errors='replace'),500),'metadata':metadata}
