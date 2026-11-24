#!/usr/bin/env python3
"""Offline-only verification for input bundle or completed runtime ZIP. Python >=3.11."""
import argparse, hashlib, io, json, re, sys, tomllib, zipfile
from pathlib import Path, PurePosixPath
from email.parser import BytesParser
COMMIT='fef168622d9ffa1d7f8f9ebb241b6932659d62aa'
SOURCE='RMAE_R2_CLI_RUNTIME_BUNDLE.zip'
SOURCE_SHA='3718219490c52357e6bf9bb2564cd46dbf9252b7b9844ad6122f2d2393b232bb'
def require(ok,msg):
    if not ok: raise ValueError(msg)
def digest(data):return hashlib.sha256(data).hexdigest()
def norm(s):return re.sub(r'[-_.]+','-',s).lower()
def openzip(data):
    z=zipfile.ZipFile(io.BytesIO(data)); names=z.namelist()
    require(len(names)==len(set(names)), 'duplicate ZIP entry')
    require(all(not PurePosixPath(n).is_absolute() and '..' not in PurePosixPath(n).parts and '\\' not in n for n in names),'unsafe ZIP path')
    require(z.testzip() is None,'ZIP CRC failure')
    return z

def manifest_check(files):
    sums=files['SHA256SUMS.txt'].decode().splitlines(); entries={}
    for line in sums:
        h,n=line.split('  ',1)
        require(n not in entries,'duplicate manifest entry '+n);entries[n]=h
    require(set(entries)==set(files)-{'SHA256SUMS.txt'},'manifest file list mismatch')
    for n,h in entries.items():require(digest(files[n])==h,'checksum mismatch '+n)
    return len(entries)
def zipfiles(z):return {n:z.read(n) for n in z.namelist() if not n.endswith('/')}
def check_inputs(files):
    m=json.loads(files['WHEEL_MANIFEST.json']); data=files[SOURCE]
    require(m['commit']==COMMIT and digest(data)==SOURCE_SHA==m['source_archive_sha256'],'source identity mismatch')
    with openzip(data) as z:
        n=manifest_check(zipfiles(z)); sm=json.loads(z.read('SOURCE_MANIFEST.json'));lock=tomllib.loads(z.read('source/uv.lock').decode()); req=z.read('requirements-runtime-lock.txt').decode()
        require(sm['commit']==COMMIT and len(sm['files'])==45,'source manifest scope mismatch')
        for f in sm['files']:
            b=z.read(f['path']);blob=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
            require(len(b)==f['bytes'] and digest(b)==f['sha256'] and blob==f['git_blob_sha1'],'source identity '+f['path'])
        require({f['path'] for f in sm['files']}=={p for p in z.namelist() if p.startswith('source/') and not p.endswith('/')},'source file list mismatch')
    wheels=m['wheels']; names={w['name'] for w in wheels}; require(len(wheels)==len(names)==10 and len({w['filename'] for w in wheels})==10,'incomplete wheel manifest')
    pk={}
    for name in names|{'aiw-ru'}:
        matches=[p for p in lock['package'] if p['name']==name];require(len(matches)==1,'ambiguous lock '+name);pk[name]=matches[0]
    closure=set();stack=['aiw-ru']
    while stack:
        k=stack.pop()
        if k in closure:continue
        require(k in pk,'missing runtime dependency '+k);closure.add(k);stack.extend(d['name'] for d in pk[k].get('dependencies',[]))
    require(closure-{'aiw-ru'}==names,'dependency closure mismatch')
    chunks={}
    for line in req.splitlines():
        mat=re.match(r'^([\w-]+)==([^\s]+)',line)
        if mat: current=mat.group(1);chunks[current]={'version':mat.group(2),'hashes':[]}
        elif '--hash=sha256:' in line:chunks[current]['hashes'].append(line.split('--hash=sha256:',1)[1].strip().rstrip('\\').strip())
    require(set(chunks)==names,'requirements names mismatch')
    for w in wheels:
        require(PurePosixPath(w['filename']).name==w['filename'] and w['url'].startswith('https://files.pythonhosted.org/') and w['url'].endswith('/'+w['filename']),'bad wheel locator')
        p=pk[w['name']];require(p['version']==w['version']==chunks[w['name']]['version'] and w['sha256'] in chunks[w['name']]['hashes'],'version or requirements mismatch '+w['name'])
        require(any(v['url']==w['url'] and v['hash']=='sha256:'+w['sha256'] and v['size']==w['size'] for v in p['wheels']),'wheel not in original lock '+w['name'])
    return m,n

def check_wheel(b,w):
    require(len(b)==w['size'] and digest(b)==w['sha256'],'wheel bytes mismatch '+w['filename'])
    with openzip(b) as z:
        mm=[n for n in z.namelist() if n.endswith('.dist-info/METADATA')];ww=[n for n in z.namelist() if n.endswith('.dist-info/WHEEL')]
        require(len(mm)==len(ww)==1 and mm[0].rsplit('/',1)[0]==ww[0].rsplit('/',1)[0],'wheel metadata missing')
        meta=BytesParser().parsebytes(z.read(mm[0]));tags=BytesParser().parsebytes(z.read(ww[0])).get_all('Tag',[])
        require(norm(meta['Name'])==norm(w['name']) and meta['Version']==w['version'],'wheel identity mismatch')
        require(any(t=='py3-none-any' or re.fullmatch(r'cp312-cp312-(?:manylinux2014_x86_64|manylinux_2_(?:17|28)_x86_64)',t) for t in tags),'wheel target tags not supported')
        return {'name':w['name'],'filename':w['filename'],'version':w['version'],'sha256':digest(b),'bytes':len(b),'tags':tags}

def main():
    p=argparse.ArgumentParser(description=__doc__);g=p.add_mutually_exclusive_group(required=True);g.add_argument('--inputs',type=Path);g.add_argument('--archive',type=Path);a=p.parse_args()
    try:
        if a.inputs:
            files={x.relative_to(a.inputs).as_posix():x.read_bytes() for x in a.inputs.rglob('*') if x.is_file()}; n=manifest_check(files);m,s=check_inputs(files)
            out={'status':'INPUTS_VERIFIED','manifest_entries':n,'source_manifest_entries':s,'source_files':45,'lock_wheels':len(m['wheels']),'actual_wheels_verified':0,'work_runtime_status':'PENDING'}
        else:
            data=a.archive.read_bytes()
            with openzip(data) as z:files=zipfiles(z)
            n=manifest_check(files);m,s=check_inputs(files);expected={'00_READ_FIRST.md','SHA256SUMS.txt','WHEEL_MANIFEST.json',SOURCE}|{'wheelhouse/'+w['filename'] for w in m['wheels']}
            require(set(files)==expected,'runtime archive has missing or extra entries')
            results=[check_wheel(files['wheelhouse/'+w['filename']],w) for w in m['wheels']]
            out={'status':'OFFLINE_BUNDLE_READY','manifest_entries':n,'source_files':45,'actual_wheels_verified':len(results),'wheels':results,'archive_sha256':digest(data),'archive_bytes':len(data),'builder_smoke_status':'NOT_RUN_BY_VERIFIER','work_runtime_status':'PENDING','scientific_acceptance':False}
        print(json.dumps(out,ensure_ascii=False,indent=2));return 0
    except Exception as e:
        print(json.dumps({'status':'BLOCKED','reason':str(e)},ensure_ascii=False));return 1
if __name__=='__main__':sys.exit(main())
