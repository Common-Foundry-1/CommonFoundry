#!/usr/bin/env python3
"""Package the frozen mainnet node/pool testing release from signed inputs."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

import release_integrity as integrity

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('miner_kit', ROOT/'scripts/package-compact-miner-kit.py')
kit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kit)
candidate = kit.candidate


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline','baseline-checksums','baseline-signature','node','compact-worker','dashboard','output','model-bank','fixed-record','launch-beacon'):
        p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--expected-commit', required=True)
    p.add_argument('--platform', choices=['linux-x86_64','windows-wsl2-x86_64'], required=True)
    p.add_argument('--ssh-keygen', default='ssh-keygen')
    args = p.parse_args()
    commit = candidate.output(['git','rev-parse','HEAD'],cwd=ROOT).decode().strip()
    if commit != args.expected_commit or candidate.output(['git','status','--porcelain'],cwd=ROOT).strip():
        raise ValueError('package only a clean frozen source checkout')
    if args.baseline.name != 'commonfoundry-mainnet-runtime-linux-x86_64-v1.0.20.tar.gz':
        raise ValueError('use the signed Linux v1.0.20 runtime baseline')
    baseline = kit.verify_baseline(args.baseline,args.baseline_checksums,args.baseline_signature,args.ssh_keygen)
    selected = {'cmfd-launch','PREPARE-V4-INPUTS.sh','production-v4-inputs.py',
        'V4-INPUT-CHUNKS.json','production-v4-rcnet-1-inputs.json',
        'FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json','prepare-runtime.sh',
        'production-mainnet/MAINNET-PLAN.json','production-v4/cmfd-v4-replay',
        'production-v4/real_bank0_relations','lib/libcudart.so.12','LICENSE','THIRD_PARTY_NOTICES.md'}
    files = {name:baseline[name] for name in selected}
    files['production-v4/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json'] = baseline['FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json']
    if args.launch_beacon.stat().st_size > 16*1024:
        raise ValueError('launch beacon exceeds its document cap')
    files['production-mainnet/LAUNCH-BEACON.json'] = args.launch_beacon.read_bytes()
    files['BASELINE-PACKAGE.json'] = baseline['MAINNET-PACKAGE.json']
    files['cmfd-node'] = args.node.read_bytes()
    files['production-v4/cmfd-direct-multigpu-worker'] = args.compact_worker.read_bytes()
    for name in ('coordinator.py','shared_model.py','cmfd-direct-multigpu-prover','LICENSE-SP1-MIT'):
        files['production-v4/'+name] = (ROOT/'tools/compact-multigpu'/name).read_bytes()
    for path in (ROOT/'packaging/compact-proof-mainnet').iterdir():
        if path.is_file():
            files[(path.name if path.suffix=='.sh' else 'production-v4/'+path.name)] = path.read_bytes()
    if not (args.dashboard/'index.html').is_file():
        raise ValueError('build the current pool dashboard')
    for path in args.dashboard.rglob('*'):
        if path.is_symlink():raise ValueError('dashboard must contain regular files')
        if path.is_file():files['dashboard/'+path.relative_to(args.dashboard).as_posix()] = path.read_bytes()
    for name in ('MAINNET-FINGERPRINT-67535.md','MAINNET-FORK-IDENTITY-67535.json','MAINNET-IMPLEMENTATION-PLAN.md','MINER-COMPATIBILITY.md'):
        files[name] = (ROOT/'docs/compact-proof-testnet'/name).read_bytes()
    files['RELEASE.allowed_signers'] = (ROOT/'packaging/mainnet/MAINNET-RELEASE.allowed_signers').read_bytes()
    files['README.md'] = b'''# Common Foundry mainnet compact fork - operator testing

Activation: 67,535. This kit enables the actual mainnet fork schedule.
Use a stopped full COPY of node/pool data and preserve the original for rollback.
Read MAINNET-IMPLEMENTATION-PLAN.md before starting. No service is installed.

Linux x86-64: glibc 2.35+, Python 3.10+, CUDA-capable NVIDIA driver for pool roles.
Windows: run the Linux payload in installed Ubuntu-22.04 under WSL2. In Windows
Terminal opened in this extracted directory, prefix commands with
`wsl -d Ubuntu-22.04 --exec`. No new native Windows EXE is included.

1. Verify the signed archive, then inspect `./cmfd-node compact-fork-info`.
   Confirm H=67535 and the published fingerprint.
2. Reuse authenticated production-v4 inputs (CMFD_MODEL_BANK/CMFD_FIXED_RECORD
   are supported by the start scripts), or run `./prepare-runtime.sh`.
   Pool inputs also require the full fixed artifact set; use
   `./PREPARE-V4-INPUTS.sh --role miner --destination "$PWD/production-v4"`
   and inspect its help for reuse options.
3. Fetch/verify the existing mainnet beacon with
   `./cmfd-launch fetch --runtime ./cmfd-node --wait`.
   Then inspect `./cmfd-node network-info` with the prepared inputs. For
   external inputs pass both absolute --production-v4-bank and
   --production-v4-fixed-record paths to that command.
4. `./start-node.sh /absolute/copied-data /absolute/passphrase-file [run options]`
   uses a loopback test port and no default peers. Add explicit peers/options
   appropriate for your test. Do not run a second instance on live data.
5. Rebind an old stopped pool ledger to a new copy using
   `./cmfd-node pool-ledger-rebind --help`; compare generation and balances.
6. `./start-pool.sh /absolute/copied-pool-data /absolute/passphrase-file [pool options]`
   requires your certificate/private key, payout policy and GPU selection.
   Use `./cmfd-node pool-serve --help` for exact options. The wrapper supplies
   test ports and the fork router; it does not copy a production pool config.
   For one GPU use explicit matching replay/proof UUIDs and serial-GPU mode.
   Split proving uses two UUIDs and standard serial handoff; shared-model is
   unavailable on this router. Keep existing fees, payouts and GPU settings.

The package inventory records every file and inherited worker provenance.
Source, signatures and qualification receipts accompany the release. Testing
publication is not an independent audit or a deployment of the live network.
'''
    for name,data in list(files.items()):
        if name.endswith(('.py','.sh','.md')) or name in ('production-v4/cmfd-mainnet-fork-prover','production-v4/cmfd-direct-multigpu-prover'):
            files[name] = data.replace(b'\r\n',b'\n')
    with tempfile.TemporaryDirectory(prefix='cmfd-fork-package-') as directory:
        stage = Path(directory)/('commonfoundry-mainnet-node-pool-v1.0.21-compact.1-'+args.platform)
        stage.mkdir()
        for name,data in files.items():
            dest=stage/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data)
            dest.chmod(integrity._canonical_file_mode(dest))
        command=[str(stage/'cmfd-node')]
        if __import__('os').name=='nt':
            path=candidate.output(['wsl.exe','-d','Ubuntu-22.04','--exec','wslpath','-u',(stage/'cmfd-node').as_posix()]).decode().strip()
            command=['wsl.exe','-d','Ubuntu-22.04','--exec',path]
        bank=str(args.model_bank.resolve(strict=True))
        record=str(args.fixed_record.resolve(strict=True))
        if __import__('os').name=='nt':
            bank=candidate.output(['wsl.exe','-d','Ubuntu-22.04','--exec','wslpath','-u',bank]).decode().strip()
            record=candidate.output(['wsl.exe','-d','Ubuntu-22.04','--exec','wslpath','-u',record]).decode().strip()
        info=json.loads(candidate.output([*command,'--production-v4-bank',bank,'--production-v4-fixed-record',record,'network-info']))
        fork=json.loads(candidate.output([*command,'compact-fork-info']))
        expected=json.loads(files['MAINNET-FORK-IDENTITY-67535.json'])
        if info['proof_of_work'].get('build_source_commit')!=commit or info['consensus']['consensus_fingerprint']!=expected['consensus_fingerprint']:
            raise ValueError('node source/network identity differs')
        if fork['activation_height']!=67535 or fork['consensus_fingerprint']!=expected['consensus_fingerprint']:
            raise ValueError('node fork schedule differs')
        for name,value in [('NODE-NETWORK-INFO.json',info),('COMPACT-FORK-INFO.json',fork)]:
            files[name]=candidate.canonical(value);(stage/name).write_bytes(files[name])
        receipt={'schema':'CMFD_MAINNET_COMPACT_FORK_PACKAGE_V1','source_commit':commit,'activation_height':67535,
            'platform':args.platform,'status':'operator-testing-prerelease','baseline_release':'v1.0.20',
            'baseline_archive_sha256':candidate.sha256(args.baseline),'consensus_fingerprint':expected['consensus_fingerprint'],
            'files':{n:{'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest()} for n,d in sorted(files.items())}}
        (stage/'FORK-PACKAGE.json').write_bytes(candidate.canonical(receipt))
        args.output.mkdir(parents=True,exist_ok=True)
        archive=args.output/(stage.name+('.zip' if args.platform.startswith('windows') else '.tar.gz'))
        epoch=int(candidate.output(['git','show','-s','--format=%ct',commit],cwd=ROOT))
        create=integrity.create_deterministic_zip if archive.suffix=='.zip' else integrity.create_deterministic_tar_gz
        create(stage,archive,epoch)
        print(json.dumps({'archive':str(archive),'sha256':candidate.sha256(archive),'source_commit':commit,'files':len(files)}))


if __name__=='__main__':main()
