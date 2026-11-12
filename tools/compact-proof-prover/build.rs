use std::{env,path::PathBuf,process::Command};
fn run(command:&mut Command){let status=command.status().expect("start local CUDA build");assert!(status.success(),"local CUDA build failed");}
fn main(){
 println!("cargo:rerun-if-env-changed=CMFD_BUILD_SOURCE_COMMIT");
 let out=PathBuf::from(env::var_os("OUT_DIR").unwrap());
 let source=PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("batch_reduction.cu");
 let object=out.join("batch_reduction.o");let library=out.join("libcmfd_batch_reduction.a");
 let nvcc=env::var_os("CUDACXX").expect("explicit pinned CUDACXX is required");
 run(Command::new(nvcc).arg("-O3").arg("-std=c++20").arg("-lineinfo").arg("-Xcompiler=-fPIC")
  .arg("-gencode=arch=compute_86,code=sm_86").arg("-gencode=arch=compute_89,code=sm_89").arg("-gencode=arch=compute_120,code=sm_120")
  .arg("-I/root/sp1-basefold-eval/sp1-gpu/crates/sys/include").arg("-c").arg(&source).arg("-o").arg(&object));
 run(Command::new("ar").arg("crs").arg(&library).arg(&object));
 if env::var_os("CARGO_FEATURE_SHARED_RESIDENT_REPLAY").is_some(){
  let shared=PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("shared-replay.cu");
  let obj=out.join("shared_replay.o");let lib=out.join("libcmfd_shared_replay.a");
  run(Command::new(env::var_os("CUDACXX").unwrap()).arg("-O3").arg("-std=c++17").arg("-Xcompiler=-fPIC")
   .arg("-gencode=arch=compute_86,code=sm_86").arg("-gencode=arch=compute_89,code=sm_89").arg("-gencode=arch=compute_120,code=sm_120")
   .arg("-I/root/cutlass-3.9.2/include").arg("-c").arg(&shared).arg("-o").arg(&obj));
  run(Command::new("ar").arg("crs").arg(&lib).arg(&obj));
  println!("cargo:rustc-link-search=native={}",out.display());println!("cargo:rustc-link-lib=static=cmfd_shared_replay");
  println!("cargo:rerun-if-changed={}",shared.display());
 }
 println!("cargo:rustc-link-search=native={}",out.display());println!("cargo:rustc-link-lib=static=cmfd_batch_reduction");
 println!("cargo:rerun-if-changed={}",source.display());println!("cargo:rerun-if-env-changed=CUDACXX");
}
