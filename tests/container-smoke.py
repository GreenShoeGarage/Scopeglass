#!/usr/bin/env python3
"""Exercise the built Docker image with a disposable volume and loopback-only scan.

Requires Docker. Does not use the installation's Compose project/config/data.
"""
import argparse
import http.cookiejar
import json
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def docker(*args,input=None,check=True):
    return subprocess.run(['docker',*args],input=input,text=True,capture_output=True,check=check,timeout=120)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',default='scopeglass:release-test')
    args=parser.parse_args()
    if not shutil.which('docker'):raise SystemExit('Docker is required. Build the image first; see RELEASE.md. No container checks ran.')
    name='scopeglass-check-'+secrets.token_hex(6);volume=name+'-data'
    password=secrets.token_urlsafe(32)
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    base=f'http://127.0.0.1:{port}';cookies=http.cookiejar.CookieJar()
    client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies),urllib.request.ProxyHandler({}))
    csrf='';epoch=''
    def request(route,body=None):
        nonlocal csrf,epoch
        headers={'Origin':base,'X-Scopeglass-CSRF':csrf,'X-Scopeglass-Epoch':epoch}
        if body is not None:headers['Content-Type']='application/json'
        req=urllib.request.Request(base+route,data=json.dumps(body).encode() if body is not None else None,headers=headers)
        try:
            with client.open(req,timeout=5) as response:
                data=json.load(response);epoch=response.headers.get('X-Scopeglass-Epoch',epoch)
                if 'csrf' in data:csrf=data['csrf']
                return response.status,data
        except urllib.error.HTTPError as error:return error.code,json.load(error)
    def ready():
        for _ in range(100):
            try:
                if request('/healthz')[0]==200:return
            except OSError:pass
            time.sleep(.1)
        raise RuntimeError('Container did not become ready')
    with tempfile.TemporaryDirectory(prefix='scopeglass-container-') as folder:
        config=Path(folder)/'config.json'
        config.write_text(json.dumps({'listen_host':'0.0.0.0','listen_port':8765,'database':'/data/scopeglass.db','allowed_cidrs':['127.0.0.0/8'],'auth':{'enabled':True},'public_origin':base}))
        config.chmod(0o644) # The container's UID 10001 must read this test-only bind mount.
        mounts=['--mount',f'type=volume,src={volume},dst=/data','--mount',f'type=bind,src={config},dst=/app/config.json,readonly']
        restrictions=['--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=32m','--cap-drop','ALL','--security-opt','no-new-privileges:true']
        try:
            docker('volume','create',volume)
            bootstrap="import json,os,sys,server,access,deployment;assert os.geteuid()==10001;server.CONFIG=deployment.load('/app/config.json');server.DB=server.CONFIG['database'];server.init_db();password=json.load(sys.stdin)['password'];\nwith server.db() as c:access.set_password(c,'admin',password)"
            docker('run','--rm','-i','--network','none',*restrictions,*mounts,args.image,'python','-c',bootstrap,input=json.dumps({'password':password}))
            docker('run','-d','--name',name,*restrictions,*mounts,'-p',f'127.0.0.1:{port}:8765',args.image)
            ready()
            assert request('/api/export')[0]==401,'Inventory must require login'
            assert request('/api/auth/login',{'username':'admin','password':password})[0]==200,'Login failed'
            status,scan=request('/api/scan',{'targets':'127.0.0.1','ports':'8765'})
            assert status==202,(status,scan)
            for _ in range(100):
                _,state=request('/api/status')
                if not state['state']['running']:break
                time.sleep(.1)
            assert not state['state']['running'],'Scan did not finish'
            status,before=request('/api/export')
            assert status==200 and len(before['observations'])==1,'Loopback port not observed'
            assert before['observations'][0]['port']==8765
            second=docker('run','--rm','--network','none',*restrictions,*mounts,args.image,check=False)
            assert second.returncode!=0 and 'already in use' in second.stderr,'Second process must refuse the same volume'
            docker('restart','--time','30',name);ready()
            status,after=request('/api/export')
            assert status==200 and after['scans']==before['scans'] and after['observations']==before['observations'],'Restart lost data/session'
            info=json.loads(docker('inspect',name).stdout)[0]
            assert info['Config']['User']=='10001:10001'
            assert info['HostConfig']['ReadonlyRootfs']
            # Execute the exact Dockerfile health command; interval status can lag this test.
            health=info['Config']['Healthcheck']['Test'];assert health[0]=='CMD-SHELL'
            docker('exec',name,'/bin/sh','-c',health[1])
            print('PASS: non-root/read-only container, account/login, protected inventory, loopback assessment, duplicate-process refusal, persistent data/session after restart, Dockerfile health check')
        except Exception:
            print(docker('logs','--tail','40',name,check=False).stderr)
            raise
        finally:
            docker('rm','-f',name,check=False)
            docker('volume','rm',volume,check=False)


if __name__=='__main__':main()
