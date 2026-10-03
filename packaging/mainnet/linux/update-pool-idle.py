#!/usr/bin/env python3
"""One-command updater for an existing standard native Linux mainnet pool."""
import hashlib,json,os,platform,shutil,signal,stat,subprocess,sys,tarfile,tempfile,time,urllib.request
from pathlib import Path

BASE='https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v1.0.0-pool.1/'
ARCHIVE='commonfoundry-linux-pool-idle-v1.0.0-pool.1.tar.gz'
ARCHIVE_SHA='7992955fddd5b37f1c340324bbd52dc1ca44885426692296e7fc08b68f5ff80f'
SUMS_SHA='dc7d76dbc940ef968c6dd02da869051b83008ad6275865d208b1610d0fda652e'
NODE_SHA='54b75ca674ac9e5edf20206b9b1ebde7281794eaa345ff70ffacb6a19063e632'
POLICY=b'commonfoundry-mainnet-owner namespaces="commonfoundry-release" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFzdrtLLbjsVvIMuxld+EwSMGzLcxzfwTrhcF/01BsLZ\n'
POLICY_SHA='9c5be92681092801d89687823837823d0966055c03a84e64551e26387da179d2'
ACTIVATION=1791046800  # October 3, 2026 17:00 UTC.
SERVICE='commonfoundry-mainnet-pool.service'
RUNTIME=Path('/opt/commonfoundry-mainnet-pool/current')
CONFIG=Path('/etc/commonfoundry-mainnet-pool/pool.json')
EXTERNAL=Path('/usr/local/lib/commonfoundry/mainnet-pool-service.py')

def sha(data):return hashlib.sha256(data).hexdigest()
def command(*args,**kwargs):
    return subprocess.run(args,check=kwargs.pop('check',True),timeout=270,capture_output=True,**kwargs)
def atomic(path,data,mode,gid=0):
    fd,name=tempfile.mkstemp(prefix='.cmfd-update-',dir=path.parent)
    temporary=Path(name)
    try:
        with os.fdopen(fd,'wb') as output:output.write(data);output.flush();os.fsync(output.fileno())
        os.chmod(temporary,mode);os.chown(temporary,0,gid);os.replace(temporary,path)
    finally:
        temporary.unlink(missing_ok=True)
def regular(path):
    item=path.lstat()
    if not stat.S_ISREG(item.st_mode) or item.st_uid!=0 or item.st_nlink!=1:
        raise ValueError('Expected a root-owned regular file: '+str(path))
    return item
def apply_update(files,config_path,runtime,external,backup_root,run=command):
    node=runtime/'cmfd-node';internal=runtime/'mainnet-pool-service.py'
    original=json.loads(config_path.read_text())
    config_stat=regular(config_path);regular(node);regular(internal)
    launch_before=json.loads(run(str(node),'mainnet-launch-info').stdout)['launch_plan']
    targets=[(node,'node'),(internal,'internal-launcher'),(config_path,'pool.json')]
    if external.exists():regular(external);targets.append((external,'external-launcher'))
    backup=Path(tempfile.mkdtemp(prefix='cmfd-pool-update-',dir=backup_root))
    for path,name in targets:shutil.copy2(path,backup/name)
    was_active=run('systemctl','is-active','--quiet',SERVICE,check=False).returncode==0
    stopped=False
    try:
        stopped=True;run('systemctl','stop',SERVICE)
        atomic(node,files['cmfd-node'],0o755)
        atomic(internal,files['mainnet-pool-service.py'],0o755)
        if external.exists():atomic(external,files['mainnet-pool-service.py'],0o755)
        updated=dict(original,expected_node_sha256=NODE_SHA,idle_gpu_search=True)
        atomic(config_path,(json.dumps(updated,indent=2)+'\n').encode(),stat.S_IMODE(config_stat.st_mode),config_stat.st_gid)
        launch_after=json.loads(run(str(node),'mainnet-launch-info').stdout)['launch_plan']
        if launch_after!=launch_before:raise ValueError('Launch plan changed; rolling back')
        run('systemctl','start',SERVICE)
        run('systemctl','is-active','--quiet',SERVICE)
        print('DONE: update installed and pool service started. Idle search is enabled.')
        print('Backup: '+str(backup))
        print('Look for worker pool-idle-search in your pool dashboard.')
    except BaseException:
        if stopped:
            run('systemctl','stop',SERVICE,check=False)
            for path,name in targets:
                saved=backup/name;item=saved.stat()
                atomic(path,saved.read_bytes(),stat.S_IMODE(item.st_mode),item.st_gid)
            if was_active:run('systemctl','start',SERVICE)
        print('Update did not complete. Original files restored; backup: '+str(backup),file=sys.stderr)
        raise
    return backup
def verified_files(stage):
    for name in (ARCHIVE,'INSTALL.md','RELEASE.json','SHA256SUMS.txt','SHA256SUMS.txt.sig'):
        with urllib.request.urlopen(BASE+name,timeout=90) as response:data=response.read(20*1024*1024)
        (stage/name).write_bytes(data)
    payload=(stage/'SHA256SUMS.txt').read_bytes()
    if sha(payload)!=SUMS_SHA or sha((stage/ARCHIVE).read_bytes())!=ARCHIVE_SHA:
        raise ValueError('Published update hash mismatch; nothing installed')
    for line in payload.decode().splitlines():
        expected,name=line.split('  ',1)
        if name not in (ARCHIVE,'INSTALL.md','RELEASE.json') or sha((stage/name).read_bytes())!=expected:
            raise ValueError('Update payload mismatch')
    if sha(POLICY)!=POLICY_SHA:raise ValueError('Embedded independent signing policy mismatch')
    policy=stage/'allowed_signers';policy.write_bytes(POLICY)
    command('ssh-keygen','-Y','verify','-f',str(policy),'-I','commonfoundry-mainnet-owner',
            '-n','commonfoundry-release','-s',str(stage/'SHA256SUMS.txt.sig'),input=payload)
    release=json.loads((stage/'RELEASE.json').read_text());files={}
    with tarfile.open(stage/ARCHIVE,'r:gz') as archive:
        for name,identity in release['files'].items():
            member=archive.getmember('commonfoundry-linux-pool-idle-v1.0.0-pool.1/'+name)
            if not member.isfile() or member.size>32*1024*1024:raise ValueError('Invalid archive member')
            data=archive.extractfile(member).read()
            if sha(data)!=identity['sha256'] or len(data)!=identity['bytes']:raise ValueError('Archive content mismatch')
            files[name]=data
    if sha(files['cmfd-node'])!=NODE_SHA:raise ValueError('Unexpected node binary')
    return files
def main():
    if sys.argv[1:]:raise ValueError('This updater accepts no path or launch overrides')
    if os.geteuid()!=0:raise ValueError('Run this updater with sudo python3')
    if platform.system()!='Linux' or platform.machine()!='x86_64':raise ValueError('Native Linux x86_64 required')
    if time.time()<ACTIVATION:
        print('Run this command again AFTER October 3 at noon Central / 17:00 UTC. No pool files changed.');return 0
    for tool in ('systemctl','ssh-keygen'):
        if not shutil.which(tool):raise ValueError('Required command missing: '+tool)
    if command('systemctl','show',SERVICE,'-p','LoadState','--value').stdout.strip()!=b'loaded':
        raise ValueError('The standard Common Foundry pool service is not installed')
    if RUNTIME.resolve().parent!=Path('/opt/commonfoundry-mainnet-pool/releases'):
        raise ValueError('Unexpected pool installation path; no changes made')
    regular(CONFIG);regular(RUNTIME/'cmfd-node');regular(RUNTIME/'mainnet-pool-service.py')
    print('Downloading and verifying the signed pool update...')
    with tempfile.TemporaryDirectory(prefix='cmfd-pool-update-') as tmp:
        stage=Path(tmp)
        files=verified_files(stage)
        config=json.loads(CONFIG.read_text())
        if config.get('idle_gpu_search') is True and sha((RUNTIME/'cmfd-node').read_bytes())==NODE_SHA:
            print('This update is already installed and enabled. No changes made.');return 0
        print('Verified. Backing up and updating your existing pool...')
        Path('/var/backups').mkdir(exist_ok=True)
        apply_update(files,CONFIG,RUNTIME,EXTERNAL,Path('/var/backups'))
if __name__=='__main__':
    def interrupt(_signal,_frame):raise RuntimeError('Update interrupted')
    signal.signal(signal.SIGTERM,interrupt)
    try:raise SystemExit(main())
    except Exception as error:print('ERROR: '+str(error),file=sys.stderr);raise SystemExit(1)
