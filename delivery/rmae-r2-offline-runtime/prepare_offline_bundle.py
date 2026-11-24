#!/usr/bin/env python3
"""Acquire only the exact wheels selected from the original lock; no code install on builder."""
from pathlib import Path
import argparse, hashlib, json, shutil, tempfile, urllib.request, zipfile

ROOT=Path(__file__).resolve().parent
def digest(data): return hashlib.sha256(data).hexdigest()
def check(data,w):
    return len(data)==w['size'] and digest(data)==w['sha256']

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--plan',action='store_true')
    p.add_argument('--cache',type=Path,help='Directory containing exact downloaded .whl files')
    p.add_argument('--output',type=Path,default=ROOT/'RMAE_R2_OFFLINE_RUNTIME.zip')
    args=p.parse_args()
    m=json.loads((ROOT/'WHEEL_MANIFEST.json').read_text(encoding='utf-8'))
    source=ROOT/m['source_archive']
    if digest(source.read_bytes())!=m['source_archive_sha256']: raise SystemExit('BLOCKED: source archive hash mismatch')
    with zipfile.ZipFile(source) as z:
        if z.testzip() is not None: raise SystemExit('BLOCKED: source ZIP corrupt')
        for line in z.read('SHA256SUMS.txt').decode().splitlines():
            h,name=line.split('  ',1)
            if digest(z.read(name))!=h: raise SystemExit('BLOCKED: source file hash mismatch '+name)
    if len(m['wheels'])!=10 or len({w['name'] for w in m['wheels']})!=10: raise SystemExit('BLOCKED: incomplete wheel manifest')
    for w in m['wheels']:
        if Path(w['filename']).name!=w['filename'] or not w['url'].startswith('https://files.pythonhosted.org/') or w['url'].rsplit('/',1)[1]!=w['filename']: raise SystemExit('BLOCKED: invalid wheel locator')
        print(w['filename'],w['sha256'],w['size'],flush=True)
    if args.plan: return
    output=args.output.resolve()
    if output.exists(): raise SystemExit('BLOCKED: output already exists; use a fresh path')
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='rmae-wheelhouse-',dir=output.parent) as tmp:
        work=Path(tmp); wh=work/'wheelhouse'; wh.mkdir()
        for w in m['wheels']:
            f=wh/w['filename']; cached=args.cache/w['filename'] if args.cache else None
            if cached and cached.is_file(): data=cached.read_bytes()
            else:
                try:
                    with urllib.request.urlopen(w['url'],timeout=60) as r: data=r.read(w['size']+1)
                except Exception as e: raise SystemExit(f"BLOCKED: {w['filename']}: {e}")
            if not check(data,w): raise SystemExit('BLOCKED: SHA-256 or size mismatch '+w['filename'])
            f.write_bytes(data); print('VERIFIED',w['filename'],flush=True)
        shutil.copyfile(source,work/source.name)
        shutil.copyfile(ROOT/'WHEEL_MANIFEST.json',work/'WHEEL_MANIFEST.json')
        shutil.copyfile(ROOT/'WORK_OFFLINE_READ_FIRST.md',work/'00_READ_FIRST.md')
        files=sorted(f for f in work.rglob('*') if f.is_file())
        sums=work/'SHA256SUMS.txt'; sums.write_text(''.join(f'{digest(f.read_bytes())}  {f.relative_to(work).as_posix()}\n' for f in files),encoding='utf-8')
        pending=work/'output.partial'
        with zipfile.ZipFile(pending,'w',compression=zipfile.ZIP_DEFLATED) as z:
            for f in files+[sums]: z.write(f,f.relative_to(work).as_posix())
        with zipfile.ZipFile(pending) as z:
            if z.testzip() is not None: raise SystemExit('BLOCKED: final ZIP corrupt')
            for line in z.read('SHA256SUMS.txt').decode().splitlines():
                h,name=line.split('  ',1)
                if digest(z.read(name))!=h: raise SystemExit('BLOCKED: final manifest mismatch '+name)
        pending.replace(output)
    print('READY',output,digest(output.read_bytes()),output.stat().st_size)

if __name__=='__main__': main()
