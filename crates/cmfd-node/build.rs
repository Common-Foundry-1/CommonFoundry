#[allow(dead_code)]
#[path = "src/network_profile.rs"]
mod network_profile;
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
    println!("cargo:rerun-if-changed=src/network_profile.rs");

    let requested = env::var_os("CARGO_FEATURE_PRODUCTION_RC").is_some()
        || ["CMFD_RELEASE_LABEL", "GITHUB_REF", "GITHUB_REF_NAME"]
            .into_iter()
            .filter_map(|variable| env::var(variable).ok())
            .any(|label| release_gate::is_production_rc_label(&label))
        || release_gate::is_production_rc_label(env!("CARGO_PKG_VERSION"));

    if requested {
        let source_commit = env::var("CMFD_BUILD_SOURCE_COMMIT").unwrap_or_default();
        let network = network_profile::RCNET1_PROFILE;
        let compiled_network_identity = release_gate::ProductionRcNetworkIdentityPin {
            network_id: network.network_id,
            virtual_genesis_hash: network.virtual_genesis_hash,
            virtual_genesis_timestamp: network.virtual_genesis_timestamp,
            bootstrap_ipv4: network.bootstrap_ipv4.octets(),
            pow_limit: network.pow_limit,
            steward_reward_destination: network.rewards.steward,
            community_reward_destination: network.rewards.community,
        };
        match release_gate::validate_production_rc_for_network(
            release_gate::COMPILED_RELEASE_PROFILE,
            &source_commit,
            compiled_network_identity,
        ) {
            Ok(()) => {
                println!("cargo:rustc-env=CMFD_BUILD_SOURCE_COMMIT={source_commit}");
            }
            Err(error) => panic!("production RC build gate: {error}"),
        }
    }
}
