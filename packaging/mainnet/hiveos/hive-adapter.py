#!/usr/bin/env python3
"""HiveOS config, process supervision and stats for the native CMFD miner."""
import argparse
import csv
import fcntl
import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time
from urllib.parse import parse_qsl, urlsplit

NAME='commonfoundry-mainnet-hiveos'
INSTALL=Path('/hive/miners/custom')/NAME
DEFAULT_DATA=Path('/hive/miners/custom/commonfoundry-data')
GPU_PATTERN=re.compile(r'GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}')
RATE=re.compile(r'MINER STATS \| (?:GPU \d+ \(GPU-[0-9a-fA-F-]+\) \| )?height \d+ \| hashrate ([0-9.]+) FW/s \| accepted (\d+) \| rejected (\d+) \| stale (\d+) \| blocks \d+ \| credit \d+ atoms \| power .*? \| efficiency .*? \| temp .*? \| uptime (\d+):(\d+):(\d+)')
TIMED_RATE=re.compile(r'^([0-9]+\.[0-9]{6}) '+RATE.pattern,re.MULTILINE)
MAX_SAMPLE_AGE=45


def validate_config(value,root):
    required={'wallet','pool','worker','gpus','model_dir','state_dir'}
    if not isinstance(value,dict) or set(value)!=required: raise ValueError('invalid miner config')
    if not isinstance(value['wallet'],str) or not re.fullmatch(r'[0-9a-fA-F]{64}',value['wallet']):
        raise ValueError('wallet template must contain the 64-character destination public key')
    pool=urlsplit(value['pool'])
    query=parse_qsl(pool.query,keep_blank_values=True)
    if pool.scheme!='cmfd+tls' or pool.username or pool.password or pool.path or pool.fragment:
        raise ValueError('use one complete cmfd+tls://IP:PORT?pin=... pool URL')
    ipaddress.IPv4Address(pool.hostname)
    if not pool.port or not 1<=pool.port<=65535 or len(query)!=1 or query[0][0]!='pin' or not re.fullmatch(r'[0-9a-fA-F]{64}',query[0][1]):
        raise ValueError('pool URL requires a numeric IPv4 address, port and 64-character certificate pin')
    if not isinstance(value['worker'],str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,24}',value['worker']):
        raise ValueError('worker name must contain 1-24 letters, numbers, dots, underscores or hyphens')
    if not isinstance(value['gpus'],list) or len(value['gpus'])>64 or any(type(gpu)!=int or not 0<=gpu<=255 for gpu in value['gpus']) or len(set(value['gpus']))!=len(value['gpus']):
        raise ValueError('gpus must be a JSON list of distinct NVIDIA GPU indices')
    for key in ('model_dir','state_dir'):
        path=Path(value[key])
        if not path.is_absolute() or len(path.parts)<4 or root==path.resolve() or root in path.resolve().parents:
            raise ValueError(key+' must be an absolute data directory outside the miner installation')
    return value


def atomic_json(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_name(path.name+'.tmp-'+str(os.getpid()))
    with temporary.open('w') as output:
        json.dump(value,output,separators=(',',':'));output.flush();os.fsync(output.fileno())
    os.replace(temporary,path)


def configure(args):
    invalid=args.config.with_suffix(args.config.suffix+'.invalid')
    invalid.parent.mkdir(parents=True,exist_ok=True)
    invalid.write_text('The latest flight-sheet configuration has not validated.\n')
    raw=os.environ.get('CMFD_HIVE_OPTIONS','').strip()
    options=json.loads(raw) if raw else {}
    if not isinstance(options,dict) or set(options)-{'worker','gpus','model_dir','state_dir'}:
        raise ValueError('extra configuration must be a JSON object with worker, gpus, model_dir or state_dir')
    template=os.environ.get('CMFD_HIVE_TEMPLATE','').strip()
    wallet,separator,template_worker=template.partition('.')
    default_worker=template_worker if separator else os.environ.get('CMFD_HIVE_WORKER','worker')
    default_worker=re.sub(r'[^A-Za-z0-9._-]','_',default_worker)[:24] or 'worker'
    value={'wallet':wallet,'pool':os.environ.get('CMFD_HIVE_URL','').strip(),
           'worker':options.get('worker',default_worker),'gpus':options.get('gpus',[]),
           'model_dir':options.get('model_dir',str(DEFAULT_DATA/'production-v4')),
           'state_dir':options.get('state_dir',str(DEFAULT_DATA/'mainnet'))}
    validate_config(value,args.root.resolve())
    atomic_json(args.config,value)
    invalid.unlink()
    print('Common Foundry config written to '+str(args.config))


def gpu_inventory():
    data=subprocess.check_output(['nvidia-smi','--query-gpu=index,uuid,pci.bus_id,temperature.gpu,fan.speed',
        '--format=csv,noheader,nounits'],text=True,timeout=15)
    result=[]
    for row in csv.reader(data.splitlines()):
        if len(row)!=5: raise ValueError('unexpected NVIDIA inventory')
        index,uuid,bus,temperature,fan=(item.strip() for item in row)
        if not GPU_PATTERN.fullmatch(uuid): raise ValueError('invalid NVIDIA GPU identity')
        def metric(text):
            try:return int(float(text))
            except ValueError:return None
        result.append({'index':int(index),'uuid':uuid,'bus':int(bus.split(':')[-2],16),
                       'temp':metric(temperature),'fan':metric(fan)})
    if not result: raise ValueError('no NVIDIA GPUs found')
    return result


def process_identity(pid):
    try:
        text=(Path('/proc')/str(pid)/'stat').read_text()
        return text[text.rfind(')')+2:].split()[19]
    except (OSError,IndexError):return None


def stop_children(children):
    for child in children:
        if child.poll() is None:
            try:os.killpg(child.pid,signal.SIGTERM)
            except ProcessLookupError:pass
    deadline=time.monotonic()+10
    for child in children:
        try:child.wait(timeout=max(0.1,deadline-time.monotonic()))
        except subprocess.TimeoutExpired:
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            child.wait()


def run(args):
    root=args.root.resolve()
    if args.config.with_suffix(args.config.suffix+'.invalid').exists():
        raise ValueError('the latest flight-sheet configuration failed; correct and regenerate it')
    config=validate_config(json.loads(args.config.read_text()),root)
    state_root=Path(config['state_dir']);state_root.mkdir(parents=True,exist_ok=True)
    instance_lock=(state_root/'hive-miner.lock').open('a')
    try:fcntl.flock(instance_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:raise ValueError('another Common Foundry HiveOS instance is using this state directory') from None
    gpus=gpu_inventory()
    if config['gpus']:
        selected=set(config['gpus']);gpus=[gpu for gpu in gpus if gpu['index'] in selected]
        if {gpu['index'] for gpu in gpus}!=selected:raise ValueError('a selected GPU is unavailable')
    log_root=args.log_base.parent;log_root.mkdir(parents=True,exist_ok=True)
    state_file=log_root/'state.json'
    state={'running':True,'manager_pid':os.getpid(),'manager_start':process_identity(os.getpid()),
           'started_at':time.time(),'workers':[]}
    children=[];collectors=[];handlers=[]
    env=dict(os.environ)
    env['LD_LIBRARY_PATH']=str(root/'lib')+(':'+env['LD_LIBRARY_PATH'] if env.get('LD_LIBRARY_PATH') else '')
    def interrupted(_signal,_frame):raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    def phase(command):
        child=subprocess.Popen(command,cwd=root,env=env,start_new_session=True)
        children.append(child)
        code=child.wait()
        if code:raise RuntimeError('preparation or launch check failed')
        children.remove(child)
    try:
        atomic_json(state_file,state)
        phase([str(root/'cmfd-miner'),'mainnet-launch-info'])
        phase([sys.executable,str(root/'production-v4-inputs.py'),
            '--chunk-manifest',str(root/'V4-INPUT-CHUNKS.json'),
            '--input-manifest',str(root/'production-v4-rcnet-1-inputs.json'),
            '--fixed-record',str(root/'FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json'),
            '--destination',config['model_dir'],'--role','pool-miner',
            '--release-base','https://downloads.commonfoundry.ai/v0.1.0-rc.1',
            '--fallback-release-base','https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v0.1.0-devnet.16'])
        phase([str(root/'cmfd-launch'),'fetch','--runtime',str(root/'cmfd-miner'),'--wait'])
        for gpu in gpus:
            scratch=Path(config['state_dir'])/'scratch'/gpu['uuid'];scratch.mkdir(parents=True,exist_ok=True)
            logfile=log_root/('gpu-'+gpu['uuid']+'.log')
            # Old-session rates must not leak into the new process's stats.
            logfile.write_text('')
            handler=RotatingFileHandler(logfile,maxBytes=2*1024*1024,backupCount=1)
            handler.setFormatter(logging.Formatter('%(cmfd_monotonic).6f %(message)s'));handlers.append(handler)
            command=[str(root/'cmfd-miner'),'pool','--pool',config['pool'],'--miner',config['wallet'],
                '--worker',config['worker'],'--gpu',gpu['uuid'],
                '--production-v4-bank',str(Path(config['model_dir'])/'MODEL-V2.bank'),
                '--production-v4-replay-worker',str(root/'cmfd-v4-replay'),
                '--production-v4-scratch',str(scratch),'--stats-seconds','5']
            child=subprocess.Popen(command,cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                text=True,encoding='utf-8',errors='replace',bufsize=1,start_new_session=True)
            children.append(child)
            def collect(stream,writer,index):
                try:
                    for line in stream:
                        text=line.rstrip('\r\n')
                        record=logging.LogRecord(NAME,logging.INFO,'',0,text,(),None)
                        record.cmfd_monotonic=time.monotonic()
                        writer.emit(record)
                        print('[GPU '+str(index)+'] '+text,flush=True)
                finally:stream.close()
            collector=threading.Thread(target=collect,args=(child.stdout,handler,gpu['index']),daemon=True)
            collector.start();collectors.append(collector)
            state['workers'].append({'gpu':gpu,'pid':child.pid,'start':process_identity(child.pid),'log':str(logfile)})
        atomic_json(state_file,state)
        while True:
            if any(child.poll() is not None for child in children):raise RuntimeError('a GPU worker exited; restarting the miner is required')
            time.sleep(1)
    except KeyboardInterrupt:pass
    finally:
        stop_children(children)
        for collector in collectors:collector.join(timeout=2)
        for handler in handlers:handler.close()
        state['running']=False;atomic_json(state_file,state)
        instance_lock.close()


def stats(args):
    empty={'khs':0,'stats':None}
    try:
        state=json.loads((args.log_base.parent/'state.json').read_text())
        if not state['running'] or process_identity(state['manager_pid'])!=state['manager_start']:return empty
        current={gpu['uuid']:gpu for gpu in gpu_inventory()}
        rates=[];temperatures=[];fans=[];buses=[];accepted=0;rejected=0;uptimes=[]
        for worker in state['workers']:
            if process_identity(worker['pid'])!=worker['start']:return empty
            path=Path(worker['log'])
            if path.is_symlink() or not path.is_file() or path.resolve().parent!=args.log_base.parent.resolve():return empty
            if time.time()-path.stat().st_mtime>MAX_SAMPLE_AGE:return empty
            with path.open('rb') as stream:
                stream.seek(max(0,path.stat().st_size-128*1024));tail=stream.read(128*1024).decode('utf-8','replace')
            matches=list(TIMED_RATE.finditer(tail))
            if not matches:return empty
            sampled_at,rate,good,bad,stale,hours,minutes,seconds=matches[-1].groups()
            # Retry/debug output must not refresh an old mining sample. The
            # collector and callback share the same system monotonic clock.
            if not 0<=time.monotonic()-float(sampled_at)<=MAX_SAMPLE_AGE:return empty
            rates.append(float(rate));accepted+=int(good);rejected+=int(bad)
            uptimes.append(int(hours)*3600+int(minutes)*60+int(seconds))
            gpu=current.get(worker['gpu']['uuid'],worker['gpu'])
            temperatures.append(gpu['temp']);fans.append(gpu['fan']);buses.append(gpu['bus'])
        if not rates:return empty
        manifest=(args.root/'h-manifest.conf').read_text()
        version=re.search(r'^CUSTOM_VERSION=(.+)$',manifest,re.MULTILINE).group(1).strip()
        return {'khs':sum(rates)/1000,'stats':{'hs':rates,'hs_units':'hs','temp':temperatures,'fan':fans,
            'uptime':min(uptimes),'ver':version,'ar':[accepted,rejected],'algo':'forgematrix_v4','bus_numbers':buses}}
    except (OSError,ValueError,KeyError,IndexError,AttributeError,subprocess.SubprocessError):return empty


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['configure','run','stats'])
    parser.add_argument('--root',type=Path,required=True);parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--log-base',type=Path,required=True);args=parser.parse_args()
    try:
        if args.action=='configure':configure(args)
        elif args.action=='run':run(args)
        else:print(json.dumps(stats(args),separators=(',',':')))
    except Exception as error:
        print('Common Foundry: '+str(error),file=sys.stderr);sys.exit(1)
