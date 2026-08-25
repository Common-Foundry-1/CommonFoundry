#[path = "release_gate.rs"]
mod release_gate;

use std::env;

fn main() {
    for variable in [
        "CMFD_RELEASE_LABEL",
        "GITHUB_REF",
        "GITHUB_REF_NAME",
        "CARGO_FEATURE_PRODUCTION_RC",
        "CMFD_BUILD_SOURCE_COMMIT",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    println!("cargo:rerun-if-changed=release_gate.rs");

    let requested = env::var_os("CARGO_FEATURE_PRODUCTION_RC").is_some()
        || ["CMFD_RELEASE_LABEL", "GITHUB_REF", "GITHUB_REF_NAME"]
            .into_iter()
            .filter_map(|variable| env::var(variable).ok())
            .any(|label| release_gate::is_production_rc_label(&label))
        || release_gate::is_production_rc_label(env!("CARGO_PKG_VERSION"));

    if requested {
        let source_commit = env::var("CMFD_BUILD_SOURCE_COMMIT").unwrap_or_default();
        match release_gate::validate_production_rc(
            release_gate::COMPILED_RELEASE_PROFILE,
            &source_commit,
        ) {
            Ok(()) => {
                println!("cargo:rustc-env=CMFD_BUILD_SOURCE_COMMIT={source_commit}");
            }
            Err(error) => panic!("production RC build gate: {error}"),
        }
    }
}
