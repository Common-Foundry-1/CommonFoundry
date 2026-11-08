"""Build a new overlay without overwriting the qualified streaming candidate."""
from pathlib import Path
import shutil
import json

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'target/compact-multigpu-speed-20261107'
GPU=OUT/'gpu-prover'
BASE=ROOT/'target/compact-public/gpu-prover'
baseline=Path(__file__).with_name('prepare-candidate.py').read_text()
old="OUT=ROOT/'target/compact-multigpu-20261107'"
assert old in baseline
exec(compile(baseline.replace(old,"OUT=ROOT/'target/compact-multigpu-speed-20261107'"),'<baseline-overlay>','exec'),{'__file__':__file__})

p=GPU/'src/bin/real_bank0_all_relations.rs';text=p.read_text()
text='#[path="../gpu_witness.rs"]\nmod gpu_witness;\n#[path="../resident.rs"]\nmod resident;\n'+text
old='run_sync_in_place(move |scope|multi_gpu::run_worker(&role,&prepared,network,&scope))??;'
assert old in text
text=text.replace(old,'''run_sync_in_place(move |scope|match role.as_str(){
            "fixed"=>resident::run_fixed(&prepared,network,&scope),
            "dynamic"=>resident::run_dynamic(&prepared,network,&scope),
            _=>multi_gpu::run_worker(&role,&prepared,network,&scope),
        })??;''')
text=text.replace('    let mut encoded_device = match resident {','    let mut encoded_device = if std::env::var("CMFD_MULTI_GPU_STAGE").as_deref()==Ok("dynamic") {DeviceBank::Spilled} else {match resident {')
text=text.replace('''    };
    eprintln!(
        "bank={bank} relation_upload_seconds''','''    }};
    eprintln!(
        "bank={bank} relation_upload_seconds''')
text=text.replace('if matches!(encoded_device,DeviceBank::Spilled){','if std::env::var("CMFD_MULTI_GPU_STAGE").as_deref()!=Ok("dynamic") && matches!(encoded_device,DeviceBank::Spilled){')
text=text.replace('let weights = reduce_weights(encoded_device.get(), &gpu_matrix_point.2, scope)?;',
 '''let weights = if std::env::var("CMFD_MULTI_GPU_STAGE").as_deref()==Ok("dynamic") {
            resident::weights(bank,&gpu_matrix_point.2,scope)?
        } else {reduce_weights(encoded_device.get(), &gpu_matrix_point.2, scope)?};''')
text=text.replace('    Pinned(PinnedBank),','    Pinned(PinnedBank),\n    Remote,')
text=text.replace('            Self::Mapped(map) => &map[..],','            Self::Mapped(map) => &map[..],\n            Self::Remote => panic!("fixed model is resident on the other GPU"),')
text=text.replace('let base_input = read_base_input(model_path)?;',
 '''let base_input = if std::env::var("CMFD_MULTI_GPU_STAGE").as_deref()==Ok("dynamic") {
        resident::shared_base_input()?
    } else {read_base_input(model_path)?};''')
at=text.index('    let encoded_banks: [EncodedBank; 3] = ')
end=text.index('    eprintln!(\n        "fixed_data_preload=',at)
old=text[at:end];rhs=old.split(' = ',1)[1].rstrip().removesuffix(';')
text=text[:at]+'''    let encoded_banks: [EncodedBank;3] = if std::env::var("CMFD_MULTI_GPU_STAGE").as_deref()==Ok("dynamic") {
        std::array::from_fn(|_|EncodedBank::Remote)
    } else {'''+rhs+'};\n'+text[end:]
p.write_text(text,newline='\n')

# Keep temporary coefficient buffers alive until their kernels have consumed
# them. This also makes the handoff independent of allocator reuse timing.
text=p.read_text()
text=text.replace('    let lifted = dot_along_dim_view(view, one.as_view(), 0);','    let lifted = dot_along_dim_view(view, one.as_view(), 0);\n    scope.synchronize_blocking()?;')
text=text.replace('''        let equality: Mle<Ext, TaskScope> = DevicePoint::from_host(&gpu_cubic_point, scope)?
            .partial_lagrange()
            .into();''','''        let equality=low_memory_sumcheck::bounded_equality(&gpu_cubic_point,scope);''')
text=text.replace('        let next_activation = lift_dynamic_half(&dynamic_tensor, BANK_VALUES, scope)?;',
'''        let next_activation = lift_dynamic_half(&dynamic_tensor, BANK_VALUES, scope)?;
        if std::env::var("CMFD_SHARED_MODEL").as_deref()==Ok("1") {gpu_witness::validate_lifts(&dynamic_tensor,&preactivation,&next_activation,scope)?;}
''')
start=text.index('fn reduce_weights(');end=text.index('\nfn gpu_last_activation_layer',start)
part=text[start:end].replace('    Ok(Mle::new(output.into_inner()))','    scope.synchronize_blocking()?;\n    Ok(Mle::new(output.into_inner()))')
text=text[:start]+part+text[end:];p.write_text(text,newline='\n')

# Keep the unchanged legacy rejection case portable to the qualification rig.
text=p.read_text()
old='let prepared=fixture::prepare(Path::new("/mnt/c/Source/_research/cmfd-snark-wrapper-20261101/standard-corpus"),43424).unwrap();'
assert old in text
text=text.replace(old,'''let fixtures=std::env::var_os("CMFD_TRANSCRIPT_FIXTURES").map(PathBuf::from).unwrap_or_else(||PathBuf::from("/mnt/c/Source/_research/cmfd-snark-wrapper-20261101/standard-corpus"));
        let prepared=fixture::prepare(&fixtures,43424).unwrap();''')
p.write_text(text,newline='\n')

p=GPU/'src/real_v4_opening.rs';text=p.read_text()
equality='''    let equality: Mle<Ext, TaskScope> = DevicePoint::from_host(point, scope)?
        .partial_lagrange()
        .into();'''
assert text.count(equality)==2
text=text.replace(equality,'    let equality=crate::low_memory_sumcheck::bounded_equality(point,scope);')
text=text.replace('    Ok(Mle::new(output.into_inner()))','    scope.synchronize_blocking()?;\n    Ok(Mle::new(output.into_inner()))')
start=text.index('pub fn prove_public_bank_opening(')
end=text.index('\nuse cmfd_consensus::forgematrix_v4_basefold::ForgeMatrixV4Field as CpuFelt;',start)
remote=text[start:end].replace('pub fn prove_public_bank_opening(','pub fn prove_public_bank_opening_remote(')
remote=remote.replace('    encoded_bank: &DeviceBuffer<u8>,\n','').replace('encoded_bank.len() == FIXED_COLUMNS * ROWS\n        && ','')
begin=remote.index('    let mut traces = Vec::with_capacity')
finish=remote.index('    scope.synchronize_blocking()?;',begin)
remote=remote[:begin]+'''    let mut traces=Vec::new();let mut equality_points=Vec::new();let mut component_claims=Vec::new();let mut fixed=Vec::new();
    for (claim,power) in gpu_claims.iter().zip(&powers) {
        let coefficients=Mle::<Ext>::partial_lagrange(&claim.column_point).guts().as_slice().iter().map(|value|*value**power).collect::<Vec<_>>();
        if claim.commitment==CpuCommitment::Fixed {
            fixed.push(crate::resident::opening_fixed_component(bank,coefficients,&claim.row_point,claim.value**power));
        } else {
            let coefficients=DeviceTensor::from_host(&Tensor::from(coefficients),scope)?;
            let row=dot_along_dim_view(dynamic_tensor.clone(),coefficients.as_view(),0);
            traces.push(Mle::new(row.reshape([1,ROWS])));scope.synchronize_blocking()?;equality_points.push(claim.row_point.clone());component_claims.push(claim.value**power);
        }
    }
    let sumcheck=crate::resident::distributed_sumcheck(traces,equality_points,component_claims,fixed,gpu_challenger,claimed_sum)?;
'''+remote[finish:]
remote=remote.replace('evaluate_fixed_columns(encoded_bank, &opening_point, scope)?','crate::resident::fixed_evaluations(bank, &opening_point)?')
text=text[:end]+'\n'+remote+text[end:]
text=text.replace('impl FixedArtifactMaps {','impl FixedArtifactMaps {\n    pub(crate) fn tree_bytes(&self)->&[u8]{&self.tree}\n',1)
old='''        let mut tree_file =
            File::open(artifact_dir.join(format!("FORGEMATRIX-V4-FIXED-BANK-{bank}.tree")))?;'''
assert old in text
text=text.replace(old,'''        let shared_tree=crate::resident::shared_tree_path(bank as usize)?;
        let mut tree_file=File::open(shared_tree.as_deref().map(Path::to_path_buf).unwrap_or_else(||artifact_dir.join(format!("FORGEMATRIX-V4-FIXED-BANK-{bank}.tree"))))?;''')
old='''        ensure!(
            blake3::Hasher::new()
                .update_rayon(&tree)
                .finalize()
                .as_bytes()
                == &artifact.tree_blake3(),
            "fixed tree digest mismatch"
        );'''
assert old in text
text=text.replace(old,'''        // The fixed service hashes its owned kernel-sealed snapshot before
        // publication. This is the same immutable inode, not a mutable cache.
        if shared_tree.is_none() {
'''+old+'\n        }')
p.write_text(text,newline='\n')
shutil.copyfile(ROOT/'tools/compact-multigpu/src/resident.rs',GPU/'src/resident.rs')
shutil.copyfile(ROOT/'tools/compact-multigpu/src/gpu_witness.rs',GPU/'src/gpu_witness.rs')
kernels=(ROOT/'tools/compact-multigpu/cuda/resident-kernels.cu').read_text()
with (OUT/'batch_reduction.cu').open('a',newline='\n') as source:source.write('\n'+kernels)

# Preserve replay arithmetic; change only optional ownership/export of its
# already-computed device witness. The ordinary sealed-host path remains.
replay=(BASE/'cuda/koala_four_limb_replay.cu').read_text()
replay='#include <atomic>\n'+replay
export=(ROOT/'tools/compact-multigpu/cuda/gpu-export.inc').read_text()
at=replay.index('void write_replay_outputs(')
replay=replay[:at]+export+'\n'+replay[at:]
start=replay.index('void write_replay_outputs(');end=replay.index('\nvoid run_dp4a_differential()',start)
body=replay[start:end].replace('void write_replay_outputs(','bool write_replay_outputs(').replace('size_t cells) {','size_t cells, const std::vector<uint32_t>& coefficients, bool pre_only) {',1).replace('if (prefix == nullptr) return;','if (prefix == nullptr) return false;',1)
body=body.replace('activation_trace + size_t(PRODUCTION_LAYERS) * cells,','activation_trace + (pre_only ? 0 : size_t(PRODUCTION_LAYERS) * cells),')
body=body.replace('    canonical_to_montgomery<<<blocks, THREADS>>>(activation_trace + cells,','    if(!pre_only) canonical_to_montgomery<<<blocks, THREADS>>>(activation_trace + cells,')
body=body.replace("(transition_values + THREADS - 1) / THREADS, 65'535","(transition_values + THREADS - 1) / THREADS, 512")
body=body.replace('    const size_t transition_values =','    gpu_witness_memory("before-witness-conversion");\n    const size_t transition_values =',1)
body=body.replace('    const size_t bank_values =','    gpu_witness_memory("after-witness-conversion");\n    const size_t bank_values =',1)
needle='    const size_t bank_values = size_t{128} * cells;'
body=body.replace(needle,'    if(gpu_witness_enabled() && gpu_replay_export().retain(prefix,preactivation_trace,pre_only?nullptr:activation_trace,cells,coefficients))return true;\n'+needle)
body=body.rstrip().removesuffix('}')+'    return false;\n}\n'
replay=replay[:start]+body+replay[end:]
replay=replay.replace('write_replay_outputs(output_prefix, preactivation_trace, activation_trace, cells);','if(write_replay_outputs(output_prefix, preactivation_trace, activation_trace, cells,coefficients,pre_only)){preactivation_trace=nullptr;if(!pre_only)activation_trace=nullptr;}')
start=replay.index('void run_production_replay(');end=replay.index('\nvoid run_production_',start+10)
body=replay[start:end]
body=body.replace('    model.ensure_loaded();','    const bool pre_only=full_trace && gpu_witness_enabled();\n    model.ensure_loaded();',1)
body=body.replace('    model.ensure_loaded();','    model.ensure_loaded();gpu_witness_memory("replay-model-ready");',1)
body=body.replace('    cudaEvent_t start{};','    gpu_witness_memory("replay-buffers-ready");\n    cudaEvent_t start{};',1)
body=body.replace('    const auto export_started =','    gpu_witness_memory("replay-compute-done");\n    const auto export_started =',1)
body=body.replace('(full_trace ? size_t(PRODUCTION_LAYERS + 1) * cells : cells)','(full_trace && !pre_only ? size_t(PRODUCTION_LAYERS + 1) * cells : cells)')
body=body.replace('uint32_t* layer_activation = full_trace','uint32_t* layer_activation = full_trace && !pre_only')
body=body.replace('const uint32_t* final_activation = full_trace','const uint32_t* final_activation = full_trace && !pre_only')
body=body.replace('double((size_t(2) * PRODUCTION_LAYERS + 1) * cells * sizeof(uint32_t))','double((pre_only ? size_t(PRODUCTION_LAYERS + 1) : (size_t(2) * PRODUCTION_LAYERS + 1)) * cells * sizeof(uint32_t))')
replay=replay[:start]+body+replay[end:]
replay=replay.replace('if (sealed_witness_enabled() && fields[1] == "search")','if (sealed_witness_enabled() && !gpu_witness_enabled() && fields[1] == "search")')
needle='        const auto fields = split_command(line);'
assert needle in replay
replay=replay.replace(needle,needle+'\n        if(gpu_witness_enabled()&&!fields.empty()&&(fields[0]=="RUN"||fields[0]=="RUNBATCH"||fields[0]=="RUNBATCHDIGEST"))gpu_replay_export().clear();',1)
(OUT/'replay-source').mkdir(exist_ok=True)
for include in (BASE/'cuda').glob('*.cuh'):
    shutil.copyfile(include,OUT/'replay-source'/include.name)
(OUT/'replay-source/koala_four_limb_replay.cu').write_text(replay,newline='\n')
record=json.loads((OUT/'BASELINE-AND-OVERLAY.json').read_text())
record.update(device_worker_gpu_cap_bytes=29<<28,mode='resident-fixed-distributed-sumcheck',
              optional_gpu_witness='preactivation-only with exact device-side activation reconstruction')
(OUT/'BASELINE-AND-OVERLAY.json').write_text(json.dumps(record,indent=2)+'\n')
print('RESIDENT_DISTRIBUTED_OVERLAY_PREPARED')
