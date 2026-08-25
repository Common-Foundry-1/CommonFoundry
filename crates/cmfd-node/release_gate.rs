//! Build-time identity gate for artifacts presented as production release candidates.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledNetworkProfile {
    Devnet,
    Rcnet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusProofSelection {
    DevnetV2Reference,
    ProductionV3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionV3ActivationEvidence {
    pub schema: &'static str,
    pub source_commit: &'static str,
    pub qualification_manifest_sha256: &'static str,
    pub independent_verifier_sha256: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompiledReleaseProfile {
    pub network: CompiledNetworkProfile,
    pub proof: ConsensusProofSelection,
    pub activation: Option<ProductionV3ActivationEvidence>,
}

/// The identity actually selected by the current source tree.
///
/// This remains intentionally blocked. A production RC build may change these
/// values only together with the real RCNet/V3 integration and committed
/// qualification evidence.
pub const COMPILED_RELEASE_PROFILE: CompiledReleaseProfile = CompiledReleaseProfile {
    network: CompiledNetworkProfile::Devnet,
    proof: ConsensusProofSelection::DevnetV2Reference,
    activation: None,
};

pub fn is_production_rc_label(label: &str) -> bool {
    let normalized = label.trim().to_ascii_lowercase();
    if normalized.is_empty() || normalized.contains("devnet") || normalized.contains("testnet") {
        return false;
    }
    let tokens = normalized
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty());
    normalized.contains("production-rc")
        || normalized.contains("production_rc")
        || normalized.contains("mainnet-rc")
        || tokens.into_iter().any(|token| {
            token == "rc"
                || token.strip_prefix("rc").is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
                })
        })
}

fn is_nonzero_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && value.bytes().any(|byte| byte != b'0')
}

pub fn validate_production_rc(profile: CompiledReleaseProfile) -> Result<(), &'static str> {
    if profile.network != CompiledNetworkProfile::Rcnet {
        return Err("compiled network profile is not RCNet");
    }
    if profile.proof != ConsensusProofSelection::ProductionV3 {
        return Err("compiled consensus proof selection is not ProductionV3");
    }
    let evidence = profile
        .activation
        .ok_or("ProductionV3 activation evidence is absent")?;
    if evidence.schema != "CMFD_PRODUCTION_V3_ACTIVATION_V1" {
        return Err("ProductionV3 activation evidence schema is unsupported");
    }
    if !is_nonzero_lower_hex(evidence.source_commit, 20)
        && !is_nonzero_lower_hex(evidence.source_commit, 32)
    {
        return Err("ProductionV3 activation evidence has an invalid source commit");
    }
    if !is_nonzero_lower_hex(evidence.qualification_manifest_sha256, 32) {
        return Err("ProductionV3 qualification manifest digest is invalid");
    }
    if !is_nonzero_lower_hex(evidence.independent_verifier_sha256, 32) {
        return Err("ProductionV3 independent verifier digest is invalid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVIDENCE: ProductionV3ActivationEvidence = ProductionV3ActivationEvidence {
        schema: "CMFD_PRODUCTION_V3_ACTIVATION_V1",
        source_commit: "1111111111111111111111111111111111111111",
        qualification_manifest_sha256: "2222222222222222222222222222222222222222222222222222222222222222",
        independent_verifier_sha256: "3333333333333333333333333333333333333333333333333333333333333333",
    };

    #[test]
    fn production_rc_labels_are_distinct_from_devnet_rc_labels() {
        for label in ["production-rc1", "mainnet-rc.2", "v1.0.0-rc1"] {
            assert!(is_production_rc_label(label), "{label}");
        }
        for label in ["0.1.0-devnet.14", "v0.1.0-devnet.14-rc1", "debug"] {
            assert!(!is_production_rc_label(label), "{label}");
        }
    }

    #[test]
    fn current_source_tree_fails_the_production_rc_gate() {
        assert_eq!(
            validate_production_rc(COMPILED_RELEASE_PROFILE),
            Err("compiled network profile is not RCNet")
        );
    }

    #[test]
    fn gate_requires_production_v3_and_activation_evidence() {
        let no_v3 = CompiledReleaseProfile {
            network: CompiledNetworkProfile::Rcnet,
            proof: ConsensusProofSelection::DevnetV2Reference,
            activation: Some(EVIDENCE),
        };
        assert_eq!(
            validate_production_rc(no_v3),
            Err("compiled consensus proof selection is not ProductionV3")
        );

        let no_evidence = CompiledReleaseProfile {
            network: CompiledNetworkProfile::Rcnet,
            proof: ConsensusProofSelection::ProductionV3,
            activation: None,
        };
        assert_eq!(
            validate_production_rc(no_evidence),
            Err("ProductionV3 activation evidence is absent")
        );
    }

    #[test]
    fn gate_accepts_only_a_complete_rcnet_v3_profile() {
        let profile = CompiledReleaseProfile {
            network: CompiledNetworkProfile::Rcnet,
            proof: ConsensusProofSelection::ProductionV3,
            activation: Some(EVIDENCE),
        };
        assert_eq!(validate_production_rc(profile), Ok(()));
    }
}
