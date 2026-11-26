fn main() {
    println!("cargo:rustc-check-cfg=cfg(cmfd_stable_avx512)");
    if std::env::var_os("CARGO_FEATURE_FORGEMATRIX_V4_EXECUTOR").is_some()
        && autocfg::new().probe_rustc_version(1, 89)
    {
        println!("cargo:rustc-cfg=cmfd_stable_avx512");
    }
}
