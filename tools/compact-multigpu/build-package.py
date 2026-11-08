#!/usr/bin/env python3
"""Assemble a local operator candidate only after full qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tarfile

ROOT=Path(__file__).resolve().parents[2]
TOOLS=Path(__file__).resolve().parent

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda:source.read(8<<20),b''):h.update(block)
    return h.hexdigest()

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--artifacts',type=Path,default=ROOT/'target/compact-multigpu-20261107')
    parser.add_argument('--base-kit',type=Path,default=ROOT/'target/compact-public/v03-release/final/commonfoundry-compact-testnet-v0.3.0-linux-x86_64')
    args=parser.parse_args();out=args.artifacts.resolve()
    qualification=json.loads((out/'FINAL-QUALIFICATION.json').read_text())
    if not qualification['success'] or not qualification['node_admission']['honest_accepted']:
        raise ValueError('complete proof and node admission must pass before packaging')
    name='commonfoundry-compact-testnet-multigpu-candidate-linux-x86_64'
    package=out/'package'/name
    package.parent.mkdir(exist_ok=True)
    if package.exists():raise ValueError('candidate package already exists')
    shutil.copytree(args.base_kit,package)
    shutil.copyfile(out/'cmfd-node',package/'cmfd-node')
    shutil.copyfile(out/'cmfd-direct-multigpu-worker',package/'cmfd-direct-multigpu-worker')
    if qualification.get('witness_transport')=='same_gpu_ipc':
        shutil.copyfile(out/'cmfd-v4-replay',package/'cmfd-v4-replay')
    for file in ['launch.py','coordinator.py','cmfd-direct-multigpu-prover','shared_model.py','cmfd-resident-replay','LICENSE-SP1-MIT']:
        shutil.copyfile(TOOLS/file,package/file)
    shutil.copyfile(TOOLS/'README.md',package/'MULTI-GPU.md')
    readme=package/'README.md'
    readme.write_text('For two-GPU proving and the 8 GB card canary, start with [MULTI-GPU.md](MULTI-GPU.md).\n\n'+readme.read_text())
    if (package/'PROOF-QUALIFICATION.json').exists():
        (package/'PROOF-QUALIFICATION.json').rename(package/'BASELINE-PROOF-QUALIFICATION.json')
    if (package/'RELEASE-QUALIFICATION.json').exists():
        (package/'RELEASE-QUALIFICATION.json').rename(package/'BASELINE-RELEASE-QUALIFICATION.json')
    (package/'PROOF-QUALIFICATION.json').write_text(json.dumps(qualification,indent=2)+'\n')
    (package/'RELEASE-QUALIFICATION.json').write_text(json.dumps(qualification,indent=2)+'\n')
    build=json.loads((package/'BUILD-INFO.json').read_text())
    build.update(version='0.3.0+multigpu-candidate',candidate='two-gpu-compact-proof',source_commit=None,source_dirty=True,
                 base_source_commit='9611f306f2477d7a8ed919a5716f3c01fe238d0c',
                 source_changes='Local reviewed worktree; see source hashes in PROOF-QUALIFICATION.json',
                 release_signed=False)
    build['source_commit_scope']='Local candidate sources identified by SHA-256 in PROOF-QUALIFICATION.json'
    if qualification.get('witness_transport')=='same_gpu_ipc':
        build.update(version='0.3.0+multigpu-resident',candidate='resident-two-gpu-compact-proof')
    if qualification.get('witness_transport')=='shared_model_host_pre_only':
        build.update(version='0.3.0+multigpu-shared-model',candidate='shared-resident-model-two-gpu-proof')
    build['qualification_report']={'path':'PROOF-QUALIFICATION.json','sha256':digest(package/'PROOF-QUALIFICATION.json'),
                                   'benchmark':qualification['compact_proof']}
    (package/'BUILD-INFO.json').write_text(json.dumps(build,indent=2)+'\n')
    manifest=json.loads((package/'PACKAGE-MANIFEST.json').read_text())
    manifest['files']={}
    excluded={'PACKAGE-MANIFEST.json','PACKAGE-SHA256SUMS.txt'}
    for path in sorted(package.rglob('*')):
        if path.is_symlink():raise ValueError('unexpected package symlink')
        if path.is_file() and path.name not in excluded:
            manifest['files'][path.relative_to(package).as_posix()]={'bytes':path.stat().st_size,'sha256':digest(path)}
    manifest['candidate']='two-gpu-compact-proof'
    (package/'PACKAGE-MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n')
    sums=''.join(f'{record["sha256"]}  {file}\n' for file,record in manifest['files'].items())
    sums+=f'{digest(package/"PACKAGE-MANIFEST.json")}  PACKAGE-MANIFEST.json\n'
    (package/'PACKAGE-SHA256SUMS.txt').write_text(sums)
    archive=out/(name+'.tar.gz')
    def metadata(info):
        file=Path(info.name).name
        executable=file.endswith('.sh') or file in {'cmfd-node','cmfd-miner','cmfd-v4-replay','cmfd-direct-prover','cmfd-direct-multigpu-worker','cmfd-direct-multigpu-prover','cmfd-resident-replay'}
        info.mode=0o755 if info.isdir() or executable else 0o644
        info.uid=info.gid=0;info.uname=info.gname=''
        return info
    with tarfile.open(archive,'w:gz',compresslevel=6) as tar:
        tar.add(package,arcname=name,filter=metadata)
    (out/'CANDIDATE-SHA256SUMS.txt').write_text(f'{digest(archive)}  {archive.name}\n')
    print(json.dumps({'archive':str(archive),'bytes':archive.stat().st_size,'sha256':digest(archive)}))

if __name__=='__main__':main()
