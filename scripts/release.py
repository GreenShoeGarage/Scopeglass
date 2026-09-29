#!/usr/bin/env python3
"""Build a reproducible source ZIP from an allowlist; never ship local config/data."""
import argparse
import ast
import hashlib
from pathlib import Path
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parents[1]
REQUIRED='server.py protocols.py searching.py monitoring.py dataops.py access.py deployment.py config.example.json README.md CHANGELOG.md TEST-REPORT.md AUDIT.md LICENSE CONTRIBUTING.md SECURITY.md RELEASE.md .gitignore .dockerignore Dockerfile compose.yaml static/index.html scripts/release.py .github/workflows/checks.yml'.split()


def build(output):
    tree=ast.parse((ROOT/'server.py').read_text())
    version=next(ast.literal_eval(node.value) for node in tree.body if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='VERSION' for target in node.targets))
    files={name:(ROOT/name).read_bytes() for name in REQUIRED}
    for pattern in ('tests/test_*.py','tests/browser-*.cjs','tests/container-smoke.py','tests/fixtures/*.sql','docs/*.png','deploy/*.md','deploy/*.json','deploy/*.service','deploy/*.example'):
        matches=sorted(ROOT.glob(pattern))
        if not matches:raise ValueError('Required release inputs missing: '+pattern)
        files.update({str(path.relative_to(ROOT)).replace('\\','/'):path.read_bytes() for path in matches})
    files['config.json']=files['config.example.json']
    if f'v{version}'.encode() not in files['README.md'] or f'v{version}'.encode() not in files['static/index.html'] or f'scopeglass:{version}'.encode() not in files['compose.yaml']:
        raise ValueError('README, UI, Compose, and server versions must agree.')
    files['SHA256SUMS']=''.join(hashlib.sha256(data).hexdigest()+'  '+name+'\n' for name,data in sorted(files.items())).encode()
    output=Path(output).resolve();output.mkdir(parents=True,exist_ok=True)
    target=output/f'SCOPEGLASS-v{version}.zip'
    with tempfile.NamedTemporaryFile(dir=output,suffix='.zip',delete=False) as temp:temporary=Path(temp.name)
    try:
        with zipfile.ZipFile(temporary,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
            for name,data in sorted(files.items()):
                entry=zipfile.ZipInfo('scopeglass/'+name,date_time=(1980,1,1,0,0,0))
                entry.create_system=3;entry.external_attr=0o100644<<16;entry.compress_type=zipfile.ZIP_DEFLATED
                archive.writestr(entry,data,compresslevel=9)
        with zipfile.ZipFile(temporary) as archive:
            if archive.testzip():raise ValueError('ZIP integrity check failed.')
            for name,data in files.items():
                if archive.read('scopeglass/'+name)!=data:raise ValueError('Packaged content mismatch: '+name)
        temporary.replace(target)
    finally:temporary.unlink(missing_ok=True)
    checksum=hashlib.sha256(target.read_bytes()).hexdigest()
    target.with_suffix('.zip.sha256').write_text(checksum+'  '+target.name+'\n')
    print(f'{target}\n{len(files)} files; {target.stat().st_size} bytes\nSHA-256 {checksum}')
    return target


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',default=str(ROOT/'dist'))
    build(parser.parse_args().output)
