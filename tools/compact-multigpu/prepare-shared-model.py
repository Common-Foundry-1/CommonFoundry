"""Build an isolated shared-model overlay; preserve the qualified resident kit."""
from pathlib import Path
import shutil
import os
ROOT=Path(__file__).resolve().parents[2];TOOLS=ROOT/'tools/compact-multigpu'
OUT=ROOT/'target/compact-witness-pipeline-20261108';GPU=OUT/'gpu-prover'
OUT=Path(os.environ.get('CMFD_COMPACT_BUILD_DIRECTORY',str(OUT))).resolve();GPU=OUT/'gpu-prover'
assert OUT.parent==ROOT/'target'
source=(TOOLS/'prepare-resident.py').read_text().replace("OUT=ROOT/'target/compact-multigpu-speed-20261107'","OUT=ROOT/"+repr(OUT.relative_to(ROOT).as_posix()))
exec(compile(source,'<resident-overlay>','exec'),{'__file__':str(TOOLS/'prepare-resident.py')})
cpp=(OUT/'replay-source/koala_four_limb_replay.cu').read_text()
cpp='#include <array>\n'+cpp
at=cpp.index('bool write_replay_outputs(')
cpp=cpp[:at]+(TOOLS/'cuda/stream-witness.inc').read_text()+'\n'+(TOOLS/'cuda/shared-model-kernels.inc').read_text()+'\n'+cpp[at:]
cpp=cpp.replace('bool pre_only) {','bool pre_only) {',1)
needle='    if(gpu_witness_enabled() && gpu_replay_export().retain('
at=cpp.index(needle)
cpp=cpp[:at]+'    if(host_pre_only_enabled()){write_host_pre_only(prefix,preactivation_trace,coefficients,cells);return false;}\n'+cpp[at:]
cpp=cpp.replace('full_trace && gpu_witness_enabled()','full_trace && (gpu_witness_enabled()||host_pre_only_enabled())')
at=cpp.index('    ProductionModel(const ProductionModel&)')
cpp=cpp[:at]+(TOOLS/'cuda/shared-model-methods.inc').read_text()+'\n'+cpp[at:]
cpp=cpp.replace('    ~ProductionModel() { evict(); }','    ~ProductionModel() { evict();if(borrowed_model_){cudaFree(device_base_);cudaFree(device_weight_row_sums_);} }')
cpp=cpp.replace('        if (weights_ == nullptr) load();','        if (!borrowed_model_ && weights_ == nullptr) load();')
cpp=cpp.replace('    void evict() {','    void evict() {\n        if(borrowed_model_){cudaDeviceSynchronize();cudaFree(weights_);weights_=nullptr;return;}',1)
cpp=cpp.replace('   private:\n    void load() {','   private:\n    bool borrowed_model_=false;\n    const uint8_t* borrowed_banks_[3]{};\n    void load() {',1)
needle='model.weights() + size_t(layer) * layer_cells'
assert cpp.count(needle)>=1
cpp=cpp.replace(needle,'model.layer_weights(layer)')
start=cpp.index('    static uint32_t capacity = 0;');end=cpp.index('    const bool wants_fused',start)
cpp=cpp[:start]+'''    auto& buffers=resident_search_buffers();
    auto& capacity=buffers.capacity;auto& limbs=buffers.limbs;auto& limbs_next=buffers.limbs_next;
    auto& limb_accumulators=buffers.limb_accumulators;auto& activations=buffers.activations;
    auto& device_coefficients=buffers.device_coefficients;auto& allocated_for_fused=buffers.allocated_for_fused;
'''+cpp[end:]
cpp=cpp.replace('        if (argc == 2 && std::string(argv[1]) == "--self-test") {','        if(argc==2 && std::string(argv[1])=="--shared-init")return 0;\n        if (argc == 2 && std::string(argv[1]) == "--self-test") {')
(OUT/'replay-source/koala_shared_replay.cu').write_text(cpp,newline='\n')
api=(TOOLS/'cuda/shared-model-api.inc').read_text()
(OUT/'shared-replay.cu').write_text('#define main cmfd_resident_replay_main\n#include "replay-source/koala_shared_replay.cu"\n#undef main\n'+api,newline='\n')
shutil.copyfile(TOOLS/'src/shared_replay.rs',GPU/'src/shared_replay.rs')
p=GPU/'src/bin/real_bank0_all_relations.rs';p.write_text('#[cfg(feature="shared-resident-replay")]\n#[path="../shared_replay.rs"]\nmod shared_replay;\n'+p.read_text(),newline='\n')
p=GPU/'Cargo.toml';p.write_text(p.read_text()+'\n[features]\nshared-resident-replay=[]\n',newline='\n')
p=GPU/'build.rs';text=p.read_text();at=text.index(' println!("cargo:rustc-link-search')
text=text[:at]+''' if env::var_os("CARGO_FEATURE_SHARED_RESIDENT_REPLAY").is_some(){
  let shared=PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("../shared-replay.cu");
  let obj=out.join("shared_replay.o");let lib=out.join("libcmfd_shared_replay.a");
  run(Command::new(env::var_os("CUDACXX").unwrap()).arg("-O3").arg("-std=c++17").arg("-Xcompiler=-fPIC")
   .arg("-gencode=arch=compute_86,code=sm_86").arg("-gencode=arch=compute_89,code=sm_89").arg("-gencode=arch=compute_120,code=sm_120")
   .arg("-I/root/cutlass-3.9.2/include").arg("-c").arg(&shared).arg("-o").arg(&obj));
  run(Command::new("ar").arg("crs").arg(&lib).arg(&obj));
  println!("cargo:rustc-link-search=native={}",out.display());println!("cargo:rustc-link-lib=static=cmfd_shared_replay");
  println!("cargo:rerun-if-changed={}",shared.display());
 }
'''+text[at:];p.write_text(text,newline='\n')
print('SHARED_MODEL_OVERLAY_PREPARED')
