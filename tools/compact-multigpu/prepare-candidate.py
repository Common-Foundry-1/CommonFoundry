"""Overlay the candidate only; the published v0.3.0 worker stays immutable."""
from pathlib import Path
import hashlib,json,shutil
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'target/compact-multigpu-20261107'
GPU=OUT/'gpu-prover'
BASE=ROOT/'target/compact-public/gpu-prover'
GPU.mkdir(parents=True,exist_ok=True)
# Recreate the overlay from the qualified baseline on every invocation.
for name in ('Cargo.toml','Cargo.lock','build.rs'):
 shutil.copyfile(BASE/name,GPU/name)
shutil.copytree(BASE/'src',GPU/'src',dirs_exist_ok=True)
shutil.copyfile(BASE.parent/'batch_reduction.cu',OUT/'batch_reduction.cu')
main=GPU/'src/bin/real_bank0_all_relations.rs'
text=main.read_text()
text='#[path="../multi_gpu.rs"]\nmod multi_gpu;\n#[path="../low_memory_sumcheck.rs"]\nmod low_memory_sumcheck;\n'+text
text=text.replace('use sp1_gpu_jagged_sumcheck::{','use low_memory_sumcheck::{')
text=text.replace('    Resident(&\'a DeviceBuffer<u8>),','    Resident(&\'a DeviceBuffer<u8>),\n    Spilled,')
text=text.replace('            Self::Resident(buffer) => buffer,','            Self::Resident(buffer) => buffer,\n            Self::Spilled => panic!("fixed bank must be reloaded before use"),')
text=text.replace('        DeviceBank::Resident(_)=>anyhow::bail!','        DeviceBank::Spilled=>anyhow::bail!("unexpected spilled bank in single-device path"),\n        DeviceBank::Resident(_)=>anyhow::bail!')
text=text.replace('    if args.first().is_some_and(|value| value == "--server") {','''    if args.first().is_some_and(|value| value == "--multi-worker") {
        ensure!(args.len()==5,"usage: --multi-worker ROLE NETWORK MODEL ARTIFACTS");
        let role=args[1].to_str().ok_or_else(||anyhow::anyhow!("invalid role"))?.to_owned();
        let network=parse_expected_network_id(&args[2])?;
        let prepared=prepare_prover(Path::new(&args[3]),Path::new(&args[4]),false)?;
        run_sync_in_place(move |scope|multi_gpu::run_worker(&role,&prepared,network,&scope))??;
        return Ok(());
    }
    if args.first().is_some_and(|value| value == "--server") {''')
text=text.replace('    let encoded_device = match resident {','    let mut encoded_device = match resident {')
text=text.replace('    sp1_gpu_cudart::TaskPoolBuilder::new()', '''    if args.first().is_some_and(|value| value=="--multi-worker") {
        let parent=unsafe{libc::getppid()};
        ensure!(parent>1,"multi-GPU coordinator is no longer running");
        ensure!(unsafe{libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL)}==0,"install worker parent-death guard");
        ensure!(unsafe{libc::getppid()}==parent,"coordinator exited during worker initialization");
    }
    sp1_gpu_cudart::TaskPoolBuilder::new()''')
text=text.replace('        let repetition_started = Instant::now();','''        if matches!(encoded_device,DeviceBank::Spilled){
            encoded_device=DeviceBank::Owned(DeviceBuffer::from_host_slice(encoded_bank,scope)?);
            scope.synchronize_blocking()?;
        }
        let repetition_started = Instant::now();''')
text=text.replace('        observe_bytes(gpu_challenger, CUBIC_PROOF_DOMAIN);','''        if std::env::var_os("CMFD_MULTI_GPU_STAGE").is_some(){
            scope.synchronize_blocking()?;
            encoded_device=DeviceBank::Spilled;
            scope.synchronize_blocking()?;
        }
        observe_bytes(gpu_challenger, CUBIC_PROOF_DOMAIN);''')
main.write_text(text,newline='\n')
p=GPU/'src/direct_opening.rs';text=p.read_text()
for name in ('direct_start','direct_statement','tag','observe_ext','fixed_data'):
 text=text.replace('fn '+name+'(', 'pub(crate) fn '+name+'(')
text=text.replace('const PCS_DOMAIN:', 'pub(crate) const PCS_DOMAIN:')
p.write_text(text,newline='\n')
p=GPU/'src/real_v4_opening.rs';text=p.read_text().replace(
 'use sp1_gpu_jagged_sumcheck::multi_hadamard_sumcheck_at_points;',
 'use crate::low_memory_sumcheck::multi_hadamard_sumcheck_at_points;')
p.write_text(text,newline='\n')
for name in ('multi_gpu.rs','low_memory_sumcheck.rs'):
 shutil.copyfile(ROOT/'tools/compact-multigpu/src'/name,GPU/'src'/name)
p=GPU/'Cargo.toml';text=p.read_text().replace('anyhow = "1"','anyhow = "1"\nnum-bigint = "0.4"')
p.write_text(text,newline='\n')
(OUT/'BASELINE-AND-OVERLAY.json').write_text(json.dumps({
 'baseline_commit':'9611f306f2477d7a8ed919a5716f3c01fe238d0c',
 'sumcheck_baseline_sha256':'8452aed19c93c512ce1bfd1bf990a61aed9d84c43fbe1adb0614aca486e57773',
 'security_parameters_changed':False,'device_worker_gpu_cap_bytes':7<<30},indent=2)+'\n')
print('ISOLATED_CANDIDATE_OVERLAY_PREPARED')
