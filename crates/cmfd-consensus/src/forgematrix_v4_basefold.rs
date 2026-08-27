//! CPU-only BaseFold types and verifier configuration for ProductionV4.
//!
//! This module deliberately contains no CUDA dependency. Relation-proof
//! parsing and transcript replay will be layered on these pinned types before
//! the dormant V4 network profile can be activated.

use slop_algebra::extension::BinomialExtensionField;
use slop_basefold::{BasefoldVerifier, FriConfig};
use slop_koala_bear::{KoalaBear, KoalaBearDegree4Duplex};

use crate::{
    FORGEMATRIX_V4_BASEFOLD_LOG_BLOWUP, FORGEMATRIX_V4_BASEFOLD_POW_BITS,
    FORGEMATRIX_V4_BASEFOLD_QUERIES,
};

pub type ForgeMatrixV4Field = KoalaBear;
pub type ForgeMatrixV4Extension = BinomialExtensionField<ForgeMatrixV4Field, 4>;
pub type ForgeMatrixV4IopContext = KoalaBearDegree4Duplex;

pub fn forgematrix_v4_basefold_verifier() -> BasefoldVerifier<ForgeMatrixV4IopContext> {
    BasefoldVerifier::new(
        FriConfig::<ForgeMatrixV4Field>::new(
            FORGEMATRIX_V4_BASEFOLD_LOG_BLOWUP as usize,
            FORGEMATRIX_V4_BASEFOLD_QUERIES as usize,
            FORGEMATRIX_V4_BASEFOLD_POW_BITS as usize,
        ),
        2,
    )
}

#[cfg(test)]
mod tests {
    use slop_algebra::PrimeField32;
    use slop_challenger::IopCtx;

    use super::*;
    use crate::{FORGEMATRIX_V4_EXTENSION_DEGREE, FORGEMATRIX_V4_FIELD_MODULUS};

    #[test]
    fn cpu_verifier_types_match_the_pinned_v4_field() {
        assert_eq!(ForgeMatrixV4Field::ORDER_U32, FORGEMATRIX_V4_FIELD_MODULUS);
        assert_eq!(
            std::mem::size_of::<ForgeMatrixV4Extension>(),
            FORGEMATRIX_V4_EXTENSION_DEGREE as usize * std::mem::size_of::<ForgeMatrixV4Field>()
        );
        let _challenger = ForgeMatrixV4IopContext::default_challenger();
        let _verifier = forgematrix_v4_basefold_verifier();
    }
}
