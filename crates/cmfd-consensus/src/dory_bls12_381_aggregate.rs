//! Bounded distinct-point opening aggregation over the BLS12-381 Dory backend.
//!
//! This module connects the deterministic BLS12-381 backend to the degree-two
//! sumcheck used by the earlier BN254 transport experiment. It remains
//! deliberately feature-gated and fail-closed for production activation.

use std::fmt;
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;

use dory_pcs::primitives::{
    DoryDeserialize, DorySerialize,
    arithmetic::{Field, Group},
    poly::{Polynomial, compute_left_right_vectors},
    serialization::{Compress, Validate},
    transcript::Transcript,
};
use dory_pcs::proof::DoryProof;
use dory_pcs::{
    FirstReduceMessage, ScalarProductMessage, SecondReduceMessage, Transparent, VMVMessage, verify,
};
use rayon::prelude::*;
use thiserror::Error;

use crate::dory_bls12_381_compact_artifact::{
    BlsDoryCompactArtifact, BlsDoryCompactArtifactError, BlsDoryCompactArtifactSpec,
    BlsDoryCompactArtifactWriter, BlsDoryMappedCompactArtifact, CompactEncodedScalar,
};
use crate::dory_bls12_381_fold_artifact::{
    BlsDoryFoldArtifact, BlsDoryFoldArtifactError, BlsDoryFoldArtifactSpec,
    BlsDoryFoldArtifactWriter,
};
#[cfg(test)]
use crate::dory_bls12_381_index_artifact::{
    BlsDoryIndexArtifact, BlsDoryIndexArtifactSpec, BlsDoryIndexArtifactWriter,
};
use crate::dory_bls12_381_prototype::{
    BlsDoryCurve, BlsDoryFr, BlsDoryG1, BlsDoryG1Routines, BlsDoryG2, BlsDoryG2Routines, BlsDoryGt,
    BlsDoryPolynomial, BlsDoryTranscript, DeterministicBlsDorySetup,
    MAX_BLS_DORY_PROTOTYPE_VARIABLES, MAX_BLS_DORY_SETUP_VARIABLES,
};
use crate::dory_bls12_381_streaming::{
    BlsDoryRowSource, prove_bls_dory_opening_from_vector_product,
};

/// Version of the bounded BLS12-381 aggregate wire grammar.
pub const BLS_DORY_AGGREGATE_VERSION: u16 = 1;
/// Degree of the distinct-point reduction sumcheck.
pub const BLS_DORY_AGGREGATE_SUMCHECK_DEGREE: usize = 2;
/// Maximum number of claims admitted by the research verifier.
pub const MAX_BLS_DORY_AGGREGATE_CLAIMS: usize = 128;
/// Exact claim count reserved for the shared-128 plus native-BLAKE3-6
/// composition. Generic public callers remain capped at 128.
#[cfg(any(test, feature = "whir-prototype"))]
pub(crate) const BLS_DORY_COMPOSED_AGGREGATE_CLAIMS: usize = 134;
/// Same proof-payload ceiling enforced by the production candidate frame.
pub const MAX_BLS_DORY_AGGREGATE_BYTES: usize = 262_128;
/// This aggregate remains unavailable to consensus activation.
pub const BLS_DORY_AGGREGATE_PRODUCTION_READY: bool = false;
/// Remaining activation blockers after replacing BN254 and random setup.
pub const BLS_DORY_AGGREGATE_PRODUCTION_BLOCKERS: [&str; 3] = [
    "bounded parallel commitments, compact transition/mapped sources with authenticated per-selector transition words and packed radix-16 nibbles, one-byte bounded activation, wiring, and model-weight sources after their first Dory row, signed-word accumulator sources, authenticated release/regeneration, consuming openings, and eight challenge-bound source-fold views preserve exact proofs; a fresh n=19 shared-layout release run retained the 84,717-byte proof, measured 100.568 seconds proving and 7.299 seconds verification, observed a 48,669,452-byte full-prover scratch peak against a 1,546,068-byte aggregate-stage projection, and left zero scratch; the exact complete n=33 aggregate-stage projection is now 29,202,416,244 bytes (about 27.2 GiB), down 15.03 times from 438,943,885,320 bytes (about 408.8 GiB), but a complete measured n=33 run remains required",
    "the executable algebraic aggregate bound exists, but Dory and Fiat-Shamir soundness have not been independently reviewed",
    "the replacement PCS and wire grammar have not received an external audit",
];

const WIRE_MAGIC: [u8; 8] = *b"CFDBLS01";
const WIRE_HEADER_BYTES: usize = 18;
const MAX_PUBLIC_BINDING_BYTES: usize = 4_096;
const ROW_COMMIT_CHUNK_BYTES: usize = 256 * 1024 * 1024;
const AGGREGATE_SOURCE_FOLD_GENERATIONS: usize = 8;
#[cfg_attr(not(test), allow(dead_code))]
const MAX_AUTHENTICATED_COEFFICIENT_RANGE_SCALARS: usize = 1 << 20;

pub(crate) fn bounded_signed_dictionary(maximum: u8) -> Option<Vec<BlsDoryFr>> {
    if maximum == 0 || maximum > 127 {
        return None;
    }
    let mut dictionary = Vec::with_capacity(1 + 2 * usize::from(maximum));
    dictionary.push(BlsDoryFr::zero());
    dictionary.extend((1..=maximum).map(|value| BlsDoryFr::from_i64(-i64::from(value))));
    dictionary.extend((1..=maximum).map(|value| BlsDoryFr::from_u64(u64::from(value))));
    Some(dictionary)
}

pub(crate) fn bounded_signed_code(value: i64, maximum: u8) -> Option<u8> {
    let maximum = i64::from(maximum);
    if maximum == 0 || maximum > 127 || value.unsigned_abs() > maximum as u64 {
        return None;
    }
    if value == 0 {
        Some(0)
    } else if value < 0 {
        u8::try_from(-value).ok()
    } else {
        u8::try_from(maximum + value).ok()
    }
}

fn is_bounded_signed_dictionary(dictionary: &[BlsDoryFr]) -> bool {
    if dictionary.len() < 3 || dictionary.len() > 255 || dictionary.len().is_multiple_of(2) {
        return false;
    }
    let maximum = (dictionary.len() - 1) / 2;
    dictionary[0] == BlsDoryFr::zero()
        && (1..=maximum).all(|value| {
            dictionary[value] == BlsDoryFr::from_i64(-(value as i64))
                && dictionary[maximum + value] == BlsDoryFr::from_u64(value as u64)
        })
}

/// One public multilinear evaluation claim against a BLS12-381 Dory commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsDoryOpeningClaim {
    pub commitment: BlsDoryGt,
    pub point: Vec<BlsDoryFr>,
    pub evaluation: BlsDoryFr,
}

/// Exact matrix partition required by one aggregate opening statement.
///
/// The total variable count alone is insufficient because Dory assigns the
/// two partitions different algebraic roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlsDoryAggregateLayout {
    nu: usize,
    sigma: usize,
}

impl BlsDoryAggregateLayout {
    pub fn new(nu: usize, sigma: usize) -> Result<Self, BlsDoryAggregateError> {
        validate_layout(nu, sigma)?;
        Ok(Self { nu, sigma })
    }

    pub fn nu(self) -> usize {
        self.nu
    }

    pub fn sigma(self) -> usize {
        self.sigma
    }

    pub fn variables(self) -> usize {
        self.nu + self.sigma
    }
}

/// A committed evaluation table retained only by the aggregate prover.
#[derive(Clone)]
pub struct BlsDoryCommittedPolynomial {
    coefficients: BlsDoryCoefficientStorage,
    commitment: BlsDoryGt,
    row_commitments: Vec<BlsDoryG1>,
    setup_identity: [u8; 32],
    nu: usize,
    sigma: usize,
}

/// Exact authenticated identity retained while a large compact coefficient
/// source is absent from scratch storage. Regeneration must reproduce every
/// field and the complete artifact digest before the source can be reopened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BlsDoryReleasedCompactSource {
    spec: BlsDoryCompactArtifactSpec,
    dictionary: Vec<BlsDoryFr>,
    digest: [u8; 32],
}

#[derive(Clone, Debug)]
struct BlsDoryReleasedMappedCompactSource {
    source: BlsDoryReleasedCompactSource,
    zero_prefix_count: u64,
    mapped_dictionary: Vec<BlsDoryFr>,
    digest: [u8; 32],
}

impl BlsDoryReleasedCompactSource {
    fn from_artifact(artifact: &BlsDoryCompactArtifact) -> Self {
        Self {
            spec: artifact.spec(),
            dictionary: artifact.dictionary().to_vec(),
            digest: artifact.digest(),
        }
    }

    /// Validate one regenerated artifact against the complete identity retained
    /// when its prior file was released. No individual identity field is
    /// sufficient: a mismatch in the framing spec, scalar dictionary, or
    /// authenticated file digest rejects the replacement.
    pub(crate) fn validate_artifact(
        &self,
        artifact: &BlsDoryCompactArtifact,
    ) -> Result<(), BlsDoryAggregateError> {
        if self.spec != artifact.spec()
            || self.dictionary != artifact.dictionary()
            || self.digest != artifact.digest()
        {
            return Err(BlsDoryAggregateError::ProverStorage);
        }
        Ok(())
    }
}

#[derive(Clone)]
enum BlsDoryCoefficientStorage {
    Materialized(BlsDoryPolynomial),
    AuthenticatedArtifact(Arc<BlsDoryFoldArtifact>),
    #[cfg(test)]
    IndexedArtifact(Arc<BlsDoryIndexArtifact>),
    CompactArtifact(Arc<BlsDoryCompactArtifact>),
    MappedCompactArtifact(Arc<BlsDoryMappedCompactArtifact>),
    ReleasedCompact(BlsDoryReleasedCompactSource),
    ReleasedMappedCompact(BlsDoryReleasedMappedCompactSource),
}

impl fmt::Debug for BlsDoryCoefficientStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Materialized(polynomial) => formatter
                .debug_struct("Materialized")
                .field("coefficient_count", &polynomial.coefficients().len())
                .finish(),
            Self::AuthenticatedArtifact(artifact) => formatter
                .debug_struct("AuthenticatedArtifact")
                .field("coefficient_count", &artifact.spec().scalar_count)
                .field("digest", &hex::encode(artifact.digest()))
                .finish(),
            #[cfg(test)]
            Self::IndexedArtifact(artifact) => formatter
                .debug_struct("IndexedArtifact")
                .field("coefficient_count", &artifact.spec().scalar_count)
                .field("digest", &hex::encode(artifact.digest()))
                .finish(),
            Self::CompactArtifact(artifact) => formatter
                .debug_struct("CompactArtifact")
                .field("coefficient_count", &artifact.spec().scalar_count)
                .field("digest", &hex::encode(artifact.digest()))
                .finish(),
            Self::MappedCompactArtifact(artifact) => formatter
                .debug_struct("MappedCompactArtifact")
                .field("coefficient_count", &artifact.scalar_count())
                .field("digest", &hex::encode(artifact.digest()))
                .finish(),
            Self::ReleasedCompact(source) => formatter
                .debug_struct("ReleasedCompact")
                .field("coefficient_count", &source.spec.scalar_count)
                .field("digest", &hex::encode(source.digest))
                .finish(),
            Self::ReleasedMappedCompact(source) => formatter
                .debug_struct("ReleasedMappedCompact")
                .field("coefficient_count", &source.source.spec.scalar_count)
                .field("digest", &hex::encode(source.digest))
                .finish(),
        }
    }
}

impl fmt::Debug for BlsDoryCommittedPolynomial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlsDoryCommittedPolynomial")
            .field("coefficients", &self.coefficients)
            .field("commitment", &self.commitment)
            .field("row_commitment_count", &self.row_commitments.len())
            .field("setup_identity", &hex::encode(self.setup_identity))
            .field("nu", &self.nu)
            .field("sigma", &self.sigma)
            .finish()
    }
}

/// Prover-only opening witnesses retained until a shared aggregate is built.
///
/// The index vector permits several claims to open the same committed
/// polynomial without cloning its coefficient table.
#[derive(Debug)]
pub(crate) struct BlsDoryDeferredOpeningSet {
    polynomials: Vec<BlsDoryCommittedPolynomial>,
    polynomial_indices: Vec<usize>,
    points: Vec<Vec<BlsDoryFr>>,
    claims: Vec<BlsDoryOpeningClaim>,
}

impl BlsDoryDeferredOpeningSet {
    pub(crate) fn unopened(
        polynomials: Vec<BlsDoryCommittedPolynomial>,
    ) -> Result<Self, BlsDoryAggregateError> {
        if polynomials.is_empty() {
            return Err(BlsDoryAggregateError::InvalidClaimCount);
        }
        let (nu, sigma) = (polynomials[0].nu, polynomials[0].sigma);
        if polynomials
            .iter()
            .any(|polynomial| polynomial.nu != nu || polynomial.sigma != sigma)
        {
            return Err(BlsDoryAggregateError::MixedStatement);
        }
        Ok(Self {
            polynomials,
            polynomial_indices: Vec::new(),
            points: Vec::new(),
            claims: Vec::new(),
        })
    }

    pub(crate) fn new(
        polynomials: Vec<BlsDoryCommittedPolynomial>,
        polynomial_indices: Vec<usize>,
        points: Vec<Vec<BlsDoryFr>>,
    ) -> Result<Self, BlsDoryAggregateError> {
        if polynomials.is_empty()
            || polynomial_indices.is_empty()
            || polynomial_indices.len() != points.len()
            || polynomial_indices
                .iter()
                .any(|index| *index >= polynomials.len())
        {
            return Err(BlsDoryAggregateError::InvalidClaimCount);
        }
        let (nu, sigma) = (polynomials[0].nu, polynomials[0].sigma);
        if polynomials
            .iter()
            .any(|polynomial| polynomial.nu != nu || polynomial.sigma != sigma)
        {
            return Err(BlsDoryAggregateError::MixedStatement);
        }
        let variables = nu + sigma;
        if points.iter().any(|point| point.len() != variables) {
            return Err(BlsDoryAggregateError::InvalidDimension);
        }
        let claims = polynomial_indices
            .iter()
            .zip(&points)
            .map(|(index, point)| {
                let polynomial = &polynomials[*index];
                Ok(BlsDoryOpeningClaim {
                    commitment: polynomial.commitment,
                    point: point.clone(),
                    evaluation: polynomial.evaluate(point)?,
                })
            })
            .collect::<Result<Vec<_>, BlsDoryAggregateError>>()?;
        Ok(Self {
            polynomials,
            polynomial_indices,
            points,
            claims,
        })
    }

    pub(crate) fn claims(&self) -> &[BlsDoryOpeningClaim] {
        &self.claims
    }

    pub(crate) fn polynomial(&self, index: usize) -> Option<&BlsDoryCommittedPolynomial> {
        self.polynomials.get(index)
    }

    /// Drop every compact coefficient handle in this set while retaining an
    /// exact authenticated identity. All compact and mapped polynomials in one
    /// set must share the same physical source.
    pub(crate) fn release_compact_source(
        &mut self,
    ) -> Result<Option<BlsDoryReleasedCompactSource>, BlsDoryAggregateError> {
        let mut expected = None;
        for polynomial in &self.polynomials {
            let Some(source) = polynomial.compact_source_identity() else {
                continue;
            };
            if expected
                .as_ref()
                .is_some_and(|expected| expected != &source)
            {
                return Err(BlsDoryAggregateError::ProverStorage);
            }
            expected = Some(source);
        }
        if expected.is_some() {
            for polynomial in &mut self.polynomials {
                polynomial.release_compact_source();
            }
        }
        Ok(expected)
    }

    /// Reattach one regenerated compact source after validating every compact
    /// and mapped identity. Replacement is transactional: no polynomial is
    /// modified unless every reconstruction validates first.
    pub(crate) fn restore_compact_source(
        &mut self,
        source: &Arc<BlsDoryCompactArtifact>,
    ) -> Result<(), BlsDoryAggregateError> {
        let replacements = self
            .polynomials
            .iter()
            .map(|polynomial| polynomial.restored_compact_coefficients(source))
            .collect::<Result<Vec<_>, _>>()?;
        if replacements.iter().all(Option::is_none) {
            return Err(BlsDoryAggregateError::ProverStorage);
        }
        for (polynomial, replacement) in self.polynomials.iter_mut().zip(replacements) {
            if let Some(replacement) = replacement {
                polynomial.coefficients = replacement;
            }
        }
        Ok(())
    }

    pub(crate) fn push_opening(
        &mut self,
        polynomial_index: usize,
        point: Vec<BlsDoryFr>,
    ) -> Result<BlsDoryOpeningClaim, BlsDoryAggregateError> {
        let polynomial = self
            .polynomials
            .get(polynomial_index)
            .ok_or(BlsDoryAggregateError::InvalidClaimCount)?;
        if point.len() != polynomial.variables() {
            return Err(BlsDoryAggregateError::InvalidDimension);
        }
        let claim = BlsDoryOpeningClaim {
            commitment: polynomial.commitment,
            evaluation: polynomial.evaluate(&point)?,
            point: point.clone(),
        };
        self.polynomial_indices.push(polynomial_index);
        self.points.push(point);
        self.claims.push(claim.clone());
        Ok(claim)
    }
}

impl BlsDoryCommittedPolynomial {
    #[cfg(feature = "whir-prototype")]
    pub(crate) fn compact_artifact_audit_metadata(
        &self,
    ) -> Result<(BlsDoryCompactArtifactSpec, [u8; 32], u64), BlsDoryAggregateError> {
        let BlsDoryCoefficientStorage::CompactArtifact(artifact) = &self.coefficients else {
            return Err(BlsDoryAggregateError::ProverStorage);
        };
        let bytes = artifact
            .spec()
            .encoded_bytes(artifact.dictionary().len())
            .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
        Ok((artifact.spec(), artifact.digest(), bytes))
    }

    fn compact_source_identity(&self) -> Option<BlsDoryReleasedCompactSource> {
        match &self.coefficients {
            BlsDoryCoefficientStorage::CompactArtifact(artifact) => {
                Some(BlsDoryReleasedCompactSource::from_artifact(artifact))
            }
            BlsDoryCoefficientStorage::MappedCompactArtifact(artifact) => Some(
                BlsDoryReleasedCompactSource::from_artifact(artifact.source()),
            ),
            BlsDoryCoefficientStorage::ReleasedCompact(source) => Some(source.clone()),
            BlsDoryCoefficientStorage::ReleasedMappedCompact(source) => Some(source.source.clone()),
            BlsDoryCoefficientStorage::Materialized(_)
            | BlsDoryCoefficientStorage::AuthenticatedArtifact(_) => None,
            #[cfg(test)]
            BlsDoryCoefficientStorage::IndexedArtifact(_) => None,
        }
    }

    fn release_compact_source(&mut self) {
        let replacement = match &self.coefficients {
            BlsDoryCoefficientStorage::CompactArtifact(artifact) => {
                Some(BlsDoryCoefficientStorage::ReleasedCompact(
                    BlsDoryReleasedCompactSource::from_artifact(artifact),
                ))
            }
            BlsDoryCoefficientStorage::MappedCompactArtifact(artifact) => {
                Some(BlsDoryCoefficientStorage::ReleasedMappedCompact(
                    BlsDoryReleasedMappedCompactSource {
                        source: BlsDoryReleasedCompactSource::from_artifact(artifact.source()),
                        zero_prefix_count: artifact.zero_prefix_count(),
                        mapped_dictionary: artifact.mapped_dictionary().to_vec(),
                        digest: artifact.digest(),
                    },
                ))
            }
            BlsDoryCoefficientStorage::Materialized(_)
            | BlsDoryCoefficientStorage::AuthenticatedArtifact(_)
            | BlsDoryCoefficientStorage::ReleasedCompact(_)
            | BlsDoryCoefficientStorage::ReleasedMappedCompact(_) => None,
            #[cfg(test)]
            BlsDoryCoefficientStorage::IndexedArtifact(_) => None,
        };
        if let Some(replacement) = replacement {
            self.coefficients = replacement;
        }
    }

    #[cfg(test)]
    pub(crate) fn release_compact_source_for_test(&mut self) {
        self.release_compact_source();
    }

    fn restored_compact_coefficients(
        &self,
        source: &Arc<BlsDoryCompactArtifact>,
    ) -> Result<Option<BlsDoryCoefficientStorage>, BlsDoryAggregateError> {
        match &self.coefficients {
            BlsDoryCoefficientStorage::ReleasedCompact(expected) => {
                expected.validate_artifact(source)?;
                Ok(Some(BlsDoryCoefficientStorage::CompactArtifact(
                    Arc::clone(source),
                )))
            }
            BlsDoryCoefficientStorage::ReleasedMappedCompact(expected) => {
                expected.source.validate_artifact(source)?;
                let mapped = BlsDoryMappedCompactArtifact::new(
                    Arc::clone(source),
                    expected.zero_prefix_count,
                    expected.mapped_dictionary.clone(),
                )
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
                if mapped.digest() != expected.digest {
                    return Err(BlsDoryAggregateError::ProverStorage);
                }
                Ok(Some(BlsDoryCoefficientStorage::MappedCompactArtifact(
                    Arc::new(mapped),
                )))
            }
            BlsDoryCoefficientStorage::Materialized(_)
            | BlsDoryCoefficientStorage::AuthenticatedArtifact(_)
            | BlsDoryCoefficientStorage::CompactArtifact(_)
            | BlsDoryCoefficientStorage::MappedCompactArtifact(_) => Ok(None),
            #[cfg(test)]
            BlsDoryCoefficientStorage::IndexedArtifact(_) => Ok(None),
        }
    }

    /// Public tier-two commitment used by the opening statement.
    #[must_use]
    pub fn commitment(&self) -> BlsDoryGt {
        self.commitment
    }

    /// Number of variables in this evaluation table.
    #[must_use]
    pub fn variables(&self) -> usize {
        self.nu + self.sigma
    }

    fn coefficient_count(&self) -> usize {
        match &self.coefficients {
            BlsDoryCoefficientStorage::Materialized(polynomial) => polynomial.coefficients().len(),
            BlsDoryCoefficientStorage::AuthenticatedArtifact(artifact) => {
                artifact.spec().scalar_count as usize
            }
            #[cfg(test)]
            BlsDoryCoefficientStorage::IndexedArtifact(artifact) => {
                artifact.spec().scalar_count as usize
            }
            BlsDoryCoefficientStorage::CompactArtifact(artifact) => {
                artifact.spec().scalar_count as usize
            }
            BlsDoryCoefficientStorage::MappedCompactArtifact(artifact) => {
                artifact.scalar_count() as usize
            }
            BlsDoryCoefficientStorage::ReleasedCompact(source)
            | BlsDoryCoefficientStorage::ReleasedMappedCompact(
                BlsDoryReleasedMappedCompactSource { source, .. },
            ) => source.spec.scalar_count as usize,
        }
    }

    pub(crate) fn explicit_coefficient_count(&self) -> usize {
        match &self.coefficients {
            BlsDoryCoefficientStorage::Materialized(polynomial) => polynomial.coefficients().len(),
            BlsDoryCoefficientStorage::AuthenticatedArtifact(artifact) => {
                artifact.spec().explicit_scalar_count as usize
            }
            #[cfg(test)]
            BlsDoryCoefficientStorage::IndexedArtifact(artifact) => {
                artifact.spec().explicit_scalar_count as usize
            }
            BlsDoryCoefficientStorage::CompactArtifact(artifact) => {
                artifact.spec().explicit_scalar_count as usize
            }
            BlsDoryCoefficientStorage::MappedCompactArtifact(artifact) => {
                artifact.explicit_scalar_count() as usize
            }
            BlsDoryCoefficientStorage::ReleasedCompact(source)
            | BlsDoryCoefficientStorage::ReleasedMappedCompact(
                BlsDoryReleasedMappedCompactSource { source, .. },
            ) => source.spec.explicit_scalar_count as usize,
        }
    }

    pub(crate) fn matches_layout(
        &self,
        layout: BlsDoryAggregateLayout,
        setup: &DeterministicBlsDorySetup,
    ) -> bool {
        self.nu == layout.nu
            && self.sigma == layout.sigma
            && self.setup_identity == setup.identity()
    }

    pub(crate) fn shares_coefficient_source(&self, other: &Self) -> bool {
        if std::ptr::eq(self, other) {
            return true;
        }
        match (&self.coefficients, &other.coefficients) {
            (
                BlsDoryCoefficientStorage::AuthenticatedArtifact(left),
                BlsDoryCoefficientStorage::AuthenticatedArtifact(right),
            ) => {
                Arc::ptr_eq(left, right)
                    && self.commitment == other.commitment
                    && self.setup_identity == other.setup_identity
                    && self.nu == other.nu
                    && self.sigma == other.sigma
            }
            #[cfg(test)]
            (
                BlsDoryCoefficientStorage::IndexedArtifact(left),
                BlsDoryCoefficientStorage::IndexedArtifact(right),
            ) => {
                Arc::ptr_eq(left, right)
                    && self.commitment == other.commitment
                    && self.setup_identity == other.setup_identity
                    && self.nu == other.nu
                    && self.sigma == other.sigma
            }
            (
                BlsDoryCoefficientStorage::CompactArtifact(left),
                BlsDoryCoefficientStorage::CompactArtifact(right),
            ) => {
                Arc::ptr_eq(left, right)
                    && self.commitment == other.commitment
                    && self.setup_identity == other.setup_identity
                    && self.nu == other.nu
                    && self.sigma == other.sigma
            }
            (
                BlsDoryCoefficientStorage::MappedCompactArtifact(left),
                BlsDoryCoefficientStorage::MappedCompactArtifact(right),
            ) => {
                Arc::ptr_eq(left, right)
                    && self.commitment == other.commitment
                    && self.setup_identity == other.setup_identity
                    && self.nu == other.nu
                    && self.sigma == other.sigma
            }
            (
                BlsDoryCoefficientStorage::ReleasedCompact(left),
                BlsDoryCoefficientStorage::ReleasedCompact(right),
            ) => {
                left == right
                    && self.commitment == other.commitment
                    && self.setup_identity == other.setup_identity
                    && self.nu == other.nu
                    && self.sigma == other.sigma
            }
            (
                BlsDoryCoefficientStorage::ReleasedMappedCompact(left),
                BlsDoryCoefficientStorage::ReleasedMappedCompact(right),
            ) => {
                left.source == right.source
                    && left.zero_prefix_count == right.zero_prefix_count
                    && left.mapped_dictionary == right.mapped_dictionary
                    && left.digest == right.digest
                    && self.commitment == other.commitment
                    && self.setup_identity == other.setup_identity
                    && self.nu == other.nu
                    && self.sigma == other.sigma
            }
            _ => false,
        }
    }

    pub(crate) fn for_each_explicit_coefficient(
        &self,
        mut visitor: impl FnMut(usize, BlsDoryFr),
    ) -> Result<(), BlsDoryAggregateError> {
        let mut visited = 0usize;
        match &self.coefficients {
            BlsDoryCoefficientStorage::Materialized(polynomial) => {
                for coefficient in polynomial.coefficients().iter().copied() {
                    visitor(visited, coefficient);
                    visited += 1;
                }
            }
            BlsDoryCoefficientStorage::AuthenticatedArtifact(artifact) => artifact
                .for_each_scalar(|coefficient| {
                    visitor(visited, coefficient);
                    visited += 1;
                    Ok(())
                })
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?,
            #[cfg(test)]
            BlsDoryCoefficientStorage::IndexedArtifact(artifact) => artifact
                .for_each_scalar(|coefficient| {
                    visitor(visited, coefficient);
                    visited += 1;
                    Ok(())
                })
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?,
            BlsDoryCoefficientStorage::CompactArtifact(artifact) => artifact
                .for_each_scalar(|coefficient| {
                    visitor(visited, coefficient);
                    visited += 1;
                    Ok(())
                })
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?,
            BlsDoryCoefficientStorage::MappedCompactArtifact(artifact) => artifact
                .for_each_scalar(|coefficient| {
                    visitor(visited, coefficient);
                    visited += 1;
                    Ok(())
                })
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?,
            BlsDoryCoefficientStorage::ReleasedCompact(_)
            | BlsDoryCoefficientStorage::ReleasedMappedCompact(_) => {
                return Err(BlsDoryAggregateError::ProverStorage);
            }
        }
        if visited != self.explicit_coefficient_count() {
            return Err(BlsDoryAggregateError::ProverStorage);
        }
        Ok(())
    }

    /// Stream one contiguous logical coefficient range in canonical row-major
    /// order. Scratch artifacts are completely authenticated before the first
    /// coefficient is exposed; only the requested stored subrange is retained
    /// during that pass, never the complete polynomial. An omitted artifact
    /// suffix is emitted as the zero range committed by the artifact
    /// specification; released compact storage remains unavailable until the
    /// caller explicitly restores the authenticated regenerated source. A
    /// request is capped at one production trace table (2^20 scalars) so this
    /// authentication buffer remains bounded.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn for_each_authenticated_coefficient_range(
        &self,
        start: usize,
        count: usize,
        mut visitor: impl FnMut(usize, BlsDoryFr) -> Result<(), BlsDoryAggregateError>,
    ) -> Result<(), BlsDoryAggregateError> {
        let end = start
            .checked_add(count)
            .ok_or(BlsDoryAggregateError::InvalidCoefficientCount)?;
        if count > MAX_AUTHENTICATED_COEFFICIENT_RANGE_SCALARS || end > self.coefficient_count() {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        let explicit_count = self.explicit_coefficient_count();
        let explicit_start = start.min(explicit_count);
        let explicit_end = end.min(explicit_count);
        let stored_count = explicit_end - explicit_start;

        match &self.coefficients {
            BlsDoryCoefficientStorage::Materialized(polynomial) => {
                for (offset, coefficient) in polynomial.coefficients()[start..end]
                    .iter()
                    .copied()
                    .enumerate()
                {
                    visitor(start + offset, coefficient)?;
                }
                return Ok(());
            }
            BlsDoryCoefficientStorage::AuthenticatedArtifact(artifact) => {
                stream_authenticated_artifact_range(
                    explicit_start,
                    stored_count,
                    explicit_count,
                    &mut visitor,
                    || BlsDoryFoldArtifactError::InvalidArtifact,
                    |range_visitor| artifact.for_each_scalar(range_visitor),
                )?;
            }
            #[cfg(test)]
            BlsDoryCoefficientStorage::IndexedArtifact(artifact) => {
                use crate::dory_bls12_381_index_artifact::BlsDoryIndexArtifactError;

                stream_authenticated_artifact_range(
                    explicit_start,
                    stored_count,
                    explicit_count,
                    &mut visitor,
                    || BlsDoryIndexArtifactError::InvalidArtifact,
                    |range_visitor| artifact.for_each_scalar(range_visitor),
                )?;
            }
            BlsDoryCoefficientStorage::CompactArtifact(artifact) => {
                stream_authenticated_artifact_range(
                    explicit_start,
                    stored_count,
                    explicit_count,
                    &mut visitor,
                    || BlsDoryCompactArtifactError::InvalidArtifact,
                    |range_visitor| artifact.for_each_scalar(range_visitor),
                )?;
            }
            BlsDoryCoefficientStorage::MappedCompactArtifact(artifact) => {
                stream_authenticated_artifact_range(
                    explicit_start,
                    stored_count,
                    explicit_count,
                    &mut visitor,
                    || BlsDoryCompactArtifactError::InvalidArtifact,
                    |range_visitor| artifact.for_each_scalar(range_visitor),
                )?;
            }
            BlsDoryCoefficientStorage::ReleasedCompact(_)
            | BlsDoryCoefficientStorage::ReleasedMappedCompact(_) => {
                return Err(BlsDoryAggregateError::ProverStorage);
            }
        }

        for index in explicit_end.max(start)..end {
            visitor(index, BlsDoryFr::zero())?;
        }
        Ok(())
    }

    fn evaluate(&self, point: &[BlsDoryFr]) -> Result<BlsDoryFr, BlsDoryAggregateError> {
        if point.len() != self.variables() {
            return Err(BlsDoryAggregateError::InvalidDimension);
        }
        match &self.coefficients {
            BlsDoryCoefficientStorage::Materialized(polynomial) => Ok(polynomial.evaluate(point)),
            BlsDoryCoefficientStorage::AuthenticatedArtifact(artifact) => {
                let mut weights = EqualityWeightIterator::new(point);
                let mut evaluation = BlsDoryFr::zero();
                let mut visited = 0usize;
                artifact
                    .for_each_scalar(|coefficient| {
                        let weight = weights
                            .next()
                            .ok_or(BlsDoryFoldArtifactError::InvalidArtifact)?;
                        evaluation = evaluation + coefficient * weight;
                        visited += 1;
                        Ok(())
                    })
                    .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
                if visited != self.explicit_coefficient_count() {
                    return Err(BlsDoryAggregateError::ProverStorage);
                }
                Ok(evaluation)
            }
            #[cfg(test)]
            BlsDoryCoefficientStorage::IndexedArtifact(artifact) => {
                let mut weights = EqualityWeightIterator::new(point);
                let mut evaluation = BlsDoryFr::zero();
                let mut visited = 0usize;
                artifact
                    .for_each_scalar(|coefficient| {
                        let weight = weights.next().ok_or(
                            crate::dory_bls12_381_index_artifact::BlsDoryIndexArtifactError::InvalidArtifact,
                        )?;
                        evaluation = evaluation + coefficient * weight;
                        visited += 1;
                        Ok(())
                    })
                    .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
                if visited != self.explicit_coefficient_count() {
                    return Err(BlsDoryAggregateError::ProverStorage);
                }
                Ok(evaluation)
            }
            BlsDoryCoefficientStorage::CompactArtifact(artifact) => {
                let mut weights = EqualityWeightIterator::new(point);
                let mut evaluation = BlsDoryFr::zero();
                let mut visited = 0usize;
                artifact
                    .for_each_scalar(|coefficient| {
                        let weight = weights
                            .next()
                            .ok_or(BlsDoryCompactArtifactError::InvalidArtifact)?;
                        evaluation = evaluation + coefficient * weight;
                        visited += 1;
                        Ok(())
                    })
                    .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
                if visited != self.explicit_coefficient_count() {
                    return Err(BlsDoryAggregateError::ProverStorage);
                }
                Ok(evaluation)
            }
            BlsDoryCoefficientStorage::MappedCompactArtifact(artifact) => {
                let mut weights = EqualityWeightIterator::new(point);
                let mut evaluation = BlsDoryFr::zero();
                let mut visited = 0usize;
                artifact
                    .for_each_scalar(|coefficient| {
                        let weight = weights
                            .next()
                            .ok_or(BlsDoryCompactArtifactError::InvalidArtifact)?;
                        evaluation = evaluation + coefficient * weight;
                        visited += 1;
                        Ok(())
                    })
                    .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
                if visited != self.explicit_coefficient_count() {
                    return Err(BlsDoryAggregateError::ProverStorage);
                }
                Ok(evaluation)
            }
            BlsDoryCoefficientStorage::ReleasedCompact(_)
            | BlsDoryCoefficientStorage::ReleasedMappedCompact(_) => {
                Err(BlsDoryAggregateError::ProverStorage)
            }
        }
    }

    fn for_each_coefficient_pair(
        &self,
        mut visitor: impl FnMut(BlsDoryFr, BlsDoryFr),
    ) -> Result<(), BlsDoryAggregateError> {
        match &self.coefficients {
            BlsDoryCoefficientStorage::Materialized(polynomial) => for_each_memory_pair(
                polynomial.coefficients(),
                polynomial.coefficients().len(),
                &mut visitor,
            ),
            BlsDoryCoefficientStorage::AuthenticatedArtifact(artifact) => artifact
                .for_each_pair(|lower, upper| {
                    visitor(lower, upper);
                    Ok(())
                })
                .map_err(|_| BlsDoryAggregateError::ProverStorage),
            #[cfg(test)]
            BlsDoryCoefficientStorage::IndexedArtifact(artifact) => artifact
                .for_each_pair(|lower, upper| {
                    visitor(lower, upper);
                    Ok(())
                })
                .map_err(|_| BlsDoryAggregateError::ProverStorage),
            BlsDoryCoefficientStorage::CompactArtifact(artifact) => artifact
                .for_each_pair(|lower, upper| {
                    visitor(lower, upper);
                    Ok(())
                })
                .map_err(|_| BlsDoryAggregateError::ProverStorage),
            BlsDoryCoefficientStorage::MappedCompactArtifact(artifact) => artifact
                .for_each_pair(|lower, upper| {
                    visitor(lower, upper);
                    Ok(())
                })
                .map_err(|_| BlsDoryAggregateError::ProverStorage),
            BlsDoryCoefficientStorage::ReleasedCompact(_)
            | BlsDoryCoefficientStorage::ReleasedMappedCompact(_) => {
                Err(BlsDoryAggregateError::ProverStorage)
            }
        }
    }

    fn accumulate_vector_matrix_product(
        &self,
        left: &[BlsDoryFr],
        scale: BlsDoryFr,
        output: &mut [BlsDoryFr],
    ) -> Result<(), BlsDoryAggregateError> {
        let rows = 1usize
            .checked_shl(
                u32::try_from(self.nu).map_err(|_| BlsDoryAggregateError::InvalidDimension)?,
            )
            .ok_or(BlsDoryAggregateError::InvalidDimension)?;
        let columns = 1usize
            .checked_shl(
                u32::try_from(self.sigma).map_err(|_| BlsDoryAggregateError::InvalidDimension)?,
            )
            .ok_or(BlsDoryAggregateError::InvalidDimension)?;
        if left.len() != rows
            || output.len() != columns
            || self.coefficient_count() != rows * columns
        {
            return Err(BlsDoryAggregateError::MixedStatement);
        }
        let mut row = 0usize;
        let mut column = 0usize;
        let mut visited = 0usize;
        let mut accumulate = |coefficient: BlsDoryFr| {
            output[column] = output[column] + scale * left[row] * coefficient;
            visited += 1;
            column += 1;
            if column == columns {
                column = 0;
                row += 1;
            }
        };
        match &self.coefficients {
            BlsDoryCoefficientStorage::Materialized(polynomial) => {
                for coefficient in polynomial.coefficients().iter().copied() {
                    accumulate(coefficient);
                }
            }
            BlsDoryCoefficientStorage::AuthenticatedArtifact(artifact) => artifact
                .for_each_scalar(|coefficient| {
                    accumulate(coefficient);
                    Ok(())
                })
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?,
            #[cfg(test)]
            BlsDoryCoefficientStorage::IndexedArtifact(artifact) => artifact
                .for_each_scalar(|coefficient| {
                    accumulate(coefficient);
                    Ok(())
                })
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?,
            BlsDoryCoefficientStorage::CompactArtifact(artifact) => artifact
                .for_each_scalar(|coefficient| {
                    accumulate(coefficient);
                    Ok(())
                })
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?,
            BlsDoryCoefficientStorage::MappedCompactArtifact(artifact) => artifact
                .for_each_scalar(|coefficient| {
                    accumulate(coefficient);
                    Ok(())
                })
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?,
            BlsDoryCoefficientStorage::ReleasedCompact(_)
            | BlsDoryCoefficientStorage::ReleasedMappedCompact(_) => {
                return Err(BlsDoryAggregateError::ProverStorage);
            }
        }
        let explicit_count = self.explicit_coefficient_count();
        if visited != explicit_count
            || row != explicit_count / columns
            || column != explicit_count % columns
        {
            return Err(BlsDoryAggregateError::ProverStorage);
        }
        Ok(())
    }

    #[cfg(test)]
    fn materialized_coefficients(&self) -> Option<&[BlsDoryFr]> {
        match &self.coefficients {
            BlsDoryCoefficientStorage::Materialized(polynomial) => Some(polynomial.coefficients()),
            BlsDoryCoefficientStorage::AuthenticatedArtifact(_)
            | BlsDoryCoefficientStorage::IndexedArtifact(_)
            | BlsDoryCoefficientStorage::CompactArtifact(_)
            | BlsDoryCoefficientStorage::MappedCompactArtifact(_)
            | BlsDoryCoefficientStorage::ReleasedCompact(_)
            | BlsDoryCoefficientStorage::ReleasedMappedCompact(_) => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn coefficient_artifact_path(&self) -> Option<&Path> {
        match &self.coefficients {
            BlsDoryCoefficientStorage::Materialized(_) => None,
            BlsDoryCoefficientStorage::AuthenticatedArtifact(artifact) => Some(artifact.path()),
            BlsDoryCoefficientStorage::IndexedArtifact(artifact) => Some(artifact.path()),
            BlsDoryCoefficientStorage::CompactArtifact(artifact) => Some(artifact.path()),
            BlsDoryCoefficientStorage::MappedCompactArtifact(artifact) => {
                Some(artifact.source_path())
            }
            BlsDoryCoefficientStorage::ReleasedCompact(_)
            | BlsDoryCoefficientStorage::ReleasedMappedCompact(_) => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn row_commitments(&self) -> &[BlsDoryG1] {
        &self.row_commitments
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn stream_authenticated_artifact_range<E>(
    start: usize,
    count: usize,
    explicit_count: usize,
    visitor: &mut impl FnMut(usize, BlsDoryFr) -> Result<(), BlsDoryAggregateError>,
    abort_error: impl Fn() -> E,
    stream: impl FnOnce(&mut dyn FnMut(BlsDoryFr) -> Result<(), E>) -> Result<(), E>,
) -> Result<(), BlsDoryAggregateError> {
    let expected_end = start
        .checked_add(count)
        .ok_or(BlsDoryAggregateError::InvalidCoefficientCount)?;
    let mut source_index = 0usize;
    let mut authenticated_range = Vec::new();
    authenticated_range
        .try_reserve_exact(count)
        .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
    let result = stream(&mut |coefficient| {
        let index = source_index;
        let Some(incremented) = source_index.checked_add(1) else {
            return Err(abort_error());
        };
        source_index = incremented;
        if (start..expected_end).contains(&index) {
            authenticated_range.push(coefficient);
        }
        Ok(())
    });
    result.map_err(|_| BlsDoryAggregateError::ProverStorage)?;
    if source_index != explicit_count || authenticated_range.len() != count {
        return Err(BlsDoryAggregateError::ProverStorage);
    }
    for (offset, coefficient) in authenticated_range.into_iter().enumerate() {
        let index = start
            .checked_add(offset)
            .ok_or(BlsDoryAggregateError::InvalidCoefficientCount)?;
        visitor(index, coefficient)?;
    }
    Ok(())
}

/// Transactional builder for one authenticated coefficient artifact and its
/// matching Dory commitment. It accepts bounded scalar chunks, commits complete
/// rows in deterministic parallel batches, and never materializes the complete
/// polynomial.
enum BlsDoryCommittedPolynomialArtifactWriter {
    Scalar(BlsDoryFoldArtifactWriter),
    SignedByte {
        writer: BlsDoryCompactArtifactWriter,
        word_scalar_count: usize,
        maximum: u8,
    },
}

pub(crate) struct BlsDoryCommittedPolynomialWriter<'a> {
    writer: BlsDoryCommittedPolynomialArtifactWriter,
    setup: &'a DeterministicBlsDorySetup,
    nu: usize,
    sigma: usize,
    rows: usize,
    columns: usize,
    explicit_count: usize,
    written: usize,
    committed_rows: usize,
    pending_capacity: usize,
    pending_scalars: Vec<BlsDoryFr>,
    row_commitments: Vec<BlsDoryG1>,
    commitment: BlsDoryGt,
}

impl<'a> BlsDoryCommittedPolynomialWriter<'a> {
    pub(crate) fn create(
        scratch_directory: &Path,
        explicit_count: usize,
        nu: usize,
        sigma: usize,
        setup: &'a DeterministicBlsDorySetup,
    ) -> Result<Self, BlsDoryAggregateError> {
        Self::create_with_chunk_bytes(
            scratch_directory,
            explicit_count,
            nu,
            sigma,
            setup,
            ROW_COMMIT_CHUNK_BYTES,
        )
    }

    pub(crate) fn create_with_chunk_bytes(
        scratch_directory: &Path,
        explicit_count: usize,
        nu: usize,
        sigma: usize,
        setup: &'a DeterministicBlsDorySetup,
        chunk_bytes: usize,
    ) -> Result<Self, BlsDoryAggregateError> {
        setup
            .validate()
            .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
        validate_layout(nu, sigma)?;
        let rows = 1usize
            .checked_shl(nu as u32)
            .ok_or(BlsDoryAggregateError::InvalidDimension)?;
        let columns = 1usize
            .checked_shl(sigma as u32)
            .ok_or(BlsDoryAggregateError::InvalidDimension)?;
        let coefficient_count = rows
            .checked_mul(columns)
            .ok_or(BlsDoryAggregateError::InvalidDimension)?;
        if explicit_count == 0
            || !explicit_count.is_power_of_two()
            || explicit_count > coefficient_count
            || setup.prover().g1_vec.len() < columns
            || setup.prover().g2_vec.len() < rows
        {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        let spec = source_artifact_spec(
            setup.identity(),
            nu,
            sigma,
            coefficient_count,
            explicit_count,
        )?;
        let writer = BlsDoryCommittedPolynomialArtifactWriter::Scalar(
            BlsDoryFoldArtifactWriter::create(scratch_directory, spec)
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?,
        );
        let row_bytes = columns
            .checked_mul(std::mem::size_of::<BlsDoryFr>())
            .ok_or(BlsDoryAggregateError::InvalidDimension)?;
        let rows_per_chunk = (chunk_bytes / row_bytes.max(1)).max(1);
        let explicit_rows = explicit_count.div_ceil(columns);
        let pending_capacity = rows_per_chunk
            .min(explicit_rows)
            .checked_mul(columns)
            .ok_or(BlsDoryAggregateError::InvalidDimension)?;
        Ok(Self {
            writer,
            setup,
            nu,
            sigma,
            rows,
            columns,
            explicit_count,
            written: 0,
            committed_rows: 0,
            pending_capacity,
            pending_scalars: Vec::new(),
            row_commitments: vec![BlsDoryG1::identity(); rows],
            commitment: BlsDoryGt::identity(),
        })
    }

    pub(crate) fn create_signed_byte(
        scratch_directory: &Path,
        explicit_count: usize,
        nu: usize,
        sigma: usize,
        maximum: u8,
        setup: &'a DeterministicBlsDorySetup,
    ) -> Result<Self, BlsDoryAggregateError> {
        setup
            .validate()
            .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
        validate_layout(nu, sigma)?;
        let rows = 1usize
            .checked_shl(nu as u32)
            .ok_or(BlsDoryAggregateError::InvalidDimension)?;
        let columns = 1usize
            .checked_shl(sigma as u32)
            .ok_or(BlsDoryAggregateError::InvalidDimension)?;
        let coefficient_count = rows
            .checked_mul(columns)
            .ok_or(BlsDoryAggregateError::InvalidDimension)?;
        let dictionary = bounded_signed_dictionary(maximum)
            .ok_or(BlsDoryAggregateError::InvalidCoefficientCount)?;
        if explicit_count == 0
            || !explicit_count.is_power_of_two()
            || explicit_count > coefficient_count
            || setup.prover().g1_vec.len() < columns
            || setup.prover().g2_vec.len() < rows
        {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        let fold_spec = source_artifact_spec(
            setup.identity(),
            nu,
            sigma,
            coefficient_count,
            explicit_count,
        )?;
        let word_scalar_count = explicit_count.min(columns);
        let compact_spec = BlsDoryCompactArtifactSpec {
            context_digest: fold_spec.context_digest,
            scalar_count: fold_spec.scalar_count,
            explicit_scalar_count: fold_spec.explicit_scalar_count,
            word_scalar_count: u64::try_from(word_scalar_count)
                .map_err(|_| BlsDoryAggregateError::InvalidDimension)?,
            word_bytes: 8,
            code_bits: 8,
            word_width_codes: 0,
            word_group_len: u64::try_from(word_scalar_count)
                .map_err(|_| BlsDoryAggregateError::InvalidDimension)?,
            signed_word_selectors: 1,
        };
        let writer = BlsDoryCommittedPolynomialArtifactWriter::SignedByte {
            writer: BlsDoryCompactArtifactWriter::create(
                scratch_directory,
                compact_spec,
                dictionary,
            )
            .map_err(|_| BlsDoryAggregateError::ProverStorage)?,
            word_scalar_count,
            maximum,
        };
        let row_bytes = columns
            .checked_mul(std::mem::size_of::<BlsDoryFr>())
            .ok_or(BlsDoryAggregateError::InvalidDimension)?;
        let rows_per_chunk = (ROW_COMMIT_CHUNK_BYTES / row_bytes.max(1)).max(1);
        let explicit_rows = explicit_count.div_ceil(columns);
        let pending_capacity = rows_per_chunk
            .min(explicit_rows)
            .checked_mul(columns)
            .ok_or(BlsDoryAggregateError::InvalidDimension)?;
        Ok(Self {
            writer,
            setup,
            nu,
            sigma,
            rows,
            columns,
            explicit_count,
            written: 0,
            committed_rows: 0,
            pending_capacity,
            pending_scalars: Vec::new(),
            row_commitments: vec![BlsDoryG1::identity(); rows],
            commitment: BlsDoryGt::identity(),
        })
    }

    pub(crate) fn write_scalars(
        &mut self,
        scalars: &[BlsDoryFr],
    ) -> Result<(), BlsDoryAggregateError> {
        if scalars.is_empty()
            || self
                .written
                .checked_add(scalars.len())
                .is_none_or(|end| end > self.explicit_count)
        {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        let BlsDoryCommittedPolynomialArtifactWriter::Scalar(writer) = &mut self.writer else {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        };
        writer
            .write_scalars(scalars)
            .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
        self.buffer_commitment_scalars(scalars)
    }

    pub(crate) fn write_signed_values(
        &mut self,
        values: &[i64],
    ) -> Result<(), BlsDoryAggregateError> {
        if values.is_empty()
            || self
                .written
                .checked_add(values.len())
                .is_none_or(|end| end > self.explicit_count)
        {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        let start = self.written;
        let BlsDoryCommittedPolynomialArtifactWriter::SignedByte {
            writer,
            word_scalar_count,
            maximum,
        } = &mut self.writer
        else {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        };
        if values
            .iter()
            .any(|value| bounded_signed_code(*value, *maximum).is_none())
        {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        let word_values = word_scalar_count.saturating_sub(start).min(values.len());
        if word_values > 0 {
            let words = values[..word_values]
                .iter()
                .map(|value| u64::from_le_bytes(value.to_le_bytes()))
                .collect::<Vec<_>>();
            writer
                .write_words(&words)
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
        }
        if word_values < values.len() {
            let codes = values[word_values..]
                .iter()
                .map(|value| bounded_signed_code(*value, *maximum).expect("validated signed code"))
                .collect::<Vec<_>>();
            writer
                .write_codes(&codes)
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
        }
        let scalars = values
            .iter()
            .copied()
            .map(BlsDoryFr::from_i64)
            .collect::<Vec<_>>();
        self.buffer_commitment_scalars(&scalars)
    }

    fn buffer_commitment_scalars(
        &mut self,
        mut scalars: &[BlsDoryFr],
    ) -> Result<(), BlsDoryAggregateError> {
        while !scalars.is_empty() {
            let take = scalars
                .len()
                .min(self.pending_capacity - self.pending_scalars.len());
            let segment = &scalars[..take];
            self.pending_scalars.extend_from_slice(segment);
            self.written += take;
            scalars = &scalars[take..];
            if self.pending_scalars.len() == self.pending_capacity {
                self.flush_pending_rows(false)?;
            }
        }
        if self.written == self.explicit_count && self.pending_scalars.is_empty() {
            self.pending_scalars = Vec::new();
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<BlsDoryCommittedPolynomial, BlsDoryAggregateError> {
        if self.written != self.explicit_count {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        if !self.pending_scalars.is_empty() {
            self.flush_pending_rows(true)?;
        }
        if self.committed_rows != self.explicit_count.div_ceil(self.columns) {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        let coefficients = match self.writer {
            BlsDoryCommittedPolynomialArtifactWriter::Scalar(writer) => {
                BlsDoryCoefficientStorage::AuthenticatedArtifact(Arc::new(
                    writer
                        .finish()
                        .map_err(|_| BlsDoryAggregateError::ProverStorage)?,
                ))
            }
            BlsDoryCommittedPolynomialArtifactWriter::SignedByte { writer, .. } => {
                BlsDoryCoefficientStorage::CompactArtifact(Arc::new(
                    writer
                        .finish()
                        .map_err(|_| BlsDoryAggregateError::ProverStorage)?,
                ))
            }
        };
        Ok(BlsDoryCommittedPolynomial {
            coefficients,
            commitment: self.commitment,
            row_commitments: self.row_commitments,
            setup_identity: self.setup.identity(),
            nu: self.nu,
            sigma: self.sigma,
        })
    }

    fn flush_pending_rows(&mut self, final_chunk: bool) -> Result<(), BlsDoryAggregateError> {
        if self.pending_scalars.is_empty()
            || (!final_chunk && !self.pending_scalars.len().is_multiple_of(self.columns))
        {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        let chunk_rows = self.pending_scalars.len().div_ceil(self.columns);
        if self
            .committed_rows
            .checked_add(chunk_rows)
            .is_none_or(|end| end > self.rows)
        {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        self.pending_scalars
            .resize(chunk_rows * self.columns, BlsDoryFr::zero());
        let chunk_start = self.committed_rows;
        let committed = self
            .pending_scalars
            .par_chunks_exact(self.columns)
            .enumerate()
            .map(|(local_row, row)| {
                let row_index = chunk_start + local_row;
                let row_commitment = self
                    .setup
                    .commit_row_segment(0, row)
                    .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
                let paired = self
                    .setup
                    .pair_committed_row(row_index, &row_commitment)
                    .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
                Ok((row_commitment, paired))
            })
            .collect::<Result<Vec<_>, BlsDoryAggregateError>>()?;
        for (local_row, (row_commitment, paired)) in committed.into_iter().enumerate() {
            self.row_commitments[chunk_start + local_row] = row_commitment;
            self.commitment = self.commitment + paired;
        }
        self.committed_rows += chunk_rows;
        self.pending_scalars.clear();
        Ok(())
    }
}

/// Errors returned by the non-production BLS aggregate.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlsDoryAggregateError {
    #[error("the BLS12-381 Dory aggregate is not production ready")]
    NotProductionReady,
    #[error("public binding exceeds the aggregate limit")]
    PublicBindingTooLarge,
    #[error("claim count is outside the aggregate limit")]
    InvalidClaimCount,
    #[error("polynomial or point dimension is outside the aggregate limit")]
    InvalidDimension,
    #[error("polynomial coefficient count does not match its dimensions")]
    InvalidCoefficientCount,
    #[error("all aggregate inputs must use one setup identity and matrix layout")]
    MixedStatement,
    #[error("deterministic setup identity or verifier precomputation is inconsistent")]
    InvalidSetup,
    #[error("proof header or fixed shape is invalid")]
    InvalidProofShape,
    #[error("proof encoding is non-canonical or malformed")]
    InvalidEncoding,
    #[error("sumcheck relation failed")]
    SumcheckFailed,
    #[error("authenticated prover scratch storage failed")]
    ProverStorage,
    #[error("coefficient row source failed")]
    CoefficientSource,
    #[error("Dory operation failed: {0}")]
    Dory(String),
}

/// Fail closed until every documented production blocker is resolved.
pub fn require_bls_dory_aggregate_production_ready() -> Result<(), BlsDoryAggregateError> {
    Err(BlsDoryAggregateError::NotProductionReady)
}

/// Project the fixed aggregate grammar using compressed BLS12-381 elements.
///
/// This is wire accounting only; the in-memory prover remains capped at 16
/// variables and cannot yet execute the production n=31 shape.
pub fn projected_bls_dory_aggregate_bytes(
    variables: usize,
) -> Result<usize, BlsDoryAggregateError> {
    if variables == 0 || variables > 64 {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }
    Ok(aggregate_wire_bytes(variables, variables.div_ceil(2)))
}

/// Commit one bounded evaluation-form polynomial under the deterministic setup.
pub fn commit_bls_dory_polynomial(
    coefficients: Vec<BlsDoryFr>,
    nu: usize,
    sigma: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryCommittedPolynomial, BlsDoryAggregateError> {
    setup
        .validate()
        .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
    validate_layout(nu, sigma)?;
    let variables = nu + sigma;
    if variables > MAX_BLS_DORY_PROTOTYPE_VARIABLES {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }
    let expected = 1usize
        .checked_shl(variables as u32)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    if coefficients.len() != expected {
        return Err(BlsDoryAggregateError::InvalidCoefficientCount);
    }
    if setup.max_log_n() < variables
        || setup.prover().g1_vec.len() < (1usize << sigma)
        || setup.prover().g2_vec.len() < (1usize << nu)
    {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }

    let polynomial = BlsDoryPolynomial::new(coefficients)
        .map_err(|error| BlsDoryAggregateError::Dory(error.to_string()))?;
    let (commitment, row_commitments, blind) = polynomial
        .commit::<BlsDoryCurve, Transparent, BlsDoryG1Routines>(nu, sigma, setup.prover())
        .map_err(dory_error)?;
    if !blind.is_zero() {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }

    Ok(BlsDoryCommittedPolynomial {
        coefficients: BlsDoryCoefficientStorage::Materialized(polynomial),
        commitment,
        row_commitments,
        setup_identity: setup.identity(),
        nu,
        sigma,
    })
}

struct BlsDoryCoefficientPrefixRowSource<'a> {
    coefficients: &'a [BlsDoryFr],
    rows: usize,
    columns: usize,
}

impl BlsDoryRowSource for BlsDoryCoefficientPrefixRowSource<'_> {
    type Error = std::convert::Infallible;

    fn rows(&self) -> usize {
        self.rows
    }

    fn columns(&self) -> usize {
        self.columns
    }

    fn explicit_scalar_count(&self) -> usize {
        self.coefficients.len()
    }

    fn read_row(
        &mut self,
        row_index: usize,
        output: &mut [BlsDoryFr],
    ) -> Result<usize, Self::Error> {
        let start = row_index * self.columns;
        for (column, scalar) in output.iter_mut().enumerate() {
            *scalar = self
                .coefficients
                .get(start + column)
                .copied()
                .unwrap_or_else(BlsDoryFr::zero);
        }
        Ok(output.len())
    }
}

/// Commit a non-empty coefficient prefix at a larger power-of-two geometry.
/// Scratch mode authenticates only the explicit prefix and treats the omitted
/// suffix as canonical zeros; memory mode preserves the original dense path.
pub(crate) fn commit_bls_dory_padded_prefix_with_optional_scratch(
    coefficients: &[BlsDoryFr],
    nu: usize,
    sigma: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: Option<&Path>,
) -> Result<BlsDoryCommittedPolynomial, BlsDoryAggregateError> {
    let rows = 1usize
        .checked_shl(u32::try_from(nu).map_err(|_| BlsDoryAggregateError::InvalidDimension)?)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let columns = 1usize
        .checked_shl(u32::try_from(sigma).map_err(|_| BlsDoryAggregateError::InvalidDimension)?)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let coefficient_count = rows
        .checked_mul(columns)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    if coefficients.is_empty() || coefficients.len() > coefficient_count {
        return Err(BlsDoryAggregateError::InvalidCoefficientCount);
    }
    if let Some(scratch_directory) = scratch_directory {
        let mut source = BlsDoryCoefficientPrefixRowSource {
            coefficients,
            rows,
            columns,
        };
        return commit_bls_dory_row_source_with_scratch(
            &mut source,
            nu,
            sigma,
            setup,
            scratch_directory,
        );
    }
    if nu + sigma > MAX_BLS_DORY_PROTOTYPE_VARIABLES {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }

    let mut padded = coefficients.to_vec();
    padded.resize(coefficient_count, BlsDoryFr::zero());
    commit_bls_dory_polynomial(padded, nu, sigma, setup)
}

/// Commit a canonical row source while retaining its coefficients only in a
/// self-authenticating scratch artifact.
///
/// The explicit source prefix is consumed exactly once in row-major order and
/// canonically encoded while the ordinary Dory row and tier-two commitments
/// are computed. The authenticated logical length makes every omitted trailing
/// scalar canonically zero. Later aggregate passes reauthenticate the complete
/// explicit prefix before using any coefficient. The scratch directory
/// must remain available until every clone of the returned polynomial is
/// dropped; any read or authentication failure aborts the proof.
pub fn commit_bls_dory_row_source_with_scratch<S: BlsDoryRowSource>(
    source: &mut S,
    nu: usize,
    sigma: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<BlsDoryCommittedPolynomial, BlsDoryAggregateError> {
    setup
        .validate()
        .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
    validate_layout(nu, sigma)?;
    let rows = 1usize
        .checked_shl(u32::try_from(nu).map_err(|_| BlsDoryAggregateError::InvalidDimension)?)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let columns = 1usize
        .checked_shl(u32::try_from(sigma).map_err(|_| BlsDoryAggregateError::InvalidDimension)?)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let coefficient_count = rows
        .checked_mul(columns)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let explicit_coefficient_count = source.explicit_scalar_count();
    if source.rows() != rows
        || source.columns() != columns
        || explicit_coefficient_count == 0
        || explicit_coefficient_count > coefficient_count
        || setup.max_log_n() < nu + sigma
        || setup.prover().g1_vec.len() < columns
        || setup.prover().g2_vec.len() < rows
    {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }

    let spec = source_artifact_spec(
        setup.identity(),
        nu,
        sigma,
        coefficient_count,
        explicit_coefficient_count,
    )?;
    let mut writer = BlsDoryFoldArtifactWriter::create(scratch_directory, spec)
        .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
    let mut row_commitments = vec![BlsDoryG1::identity(); rows];
    let mut commitment = BlsDoryGt::identity();
    let explicit_rows = explicit_coefficient_count.div_ceil(columns);
    let row_bytes = columns
        .checked_mul(std::mem::size_of::<BlsDoryFr>())
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let rows_per_chunk = (ROW_COMMIT_CHUNK_BYTES / row_bytes.max(1)).max(1);
    for chunk_start in (0..explicit_rows).step_by(rows_per_chunk) {
        let chunk_end = chunk_start
            .saturating_add(rows_per_chunk)
            .min(explicit_rows);
        let chunk_rows = chunk_end - chunk_start;
        let chunk_scalars = chunk_rows
            .checked_mul(columns)
            .ok_or(BlsDoryAggregateError::InvalidDimension)?;
        let mut coefficients = vec![BlsDoryFr::zero(); chunk_scalars];
        for (local_row, row) in coefficients.chunks_exact_mut(columns).enumerate() {
            let row_index = chunk_start + local_row;
            let written = source
                .read_row(row_index, row)
                .map_err(|_| BlsDoryAggregateError::CoefficientSource)?;
            if written != columns {
                return Err(BlsDoryAggregateError::InvalidCoefficientCount);
            }
            let explicit_in_row = explicit_coefficient_count
                .saturating_sub(row_index * columns)
                .min(columns);
            row[explicit_in_row..].fill(BlsDoryFr::zero());
        }
        let committed_rows = coefficients
            .par_chunks_exact(columns)
            .enumerate()
            .map(|(local_row, row)| {
                let row_index = chunk_start + local_row;
                let row_commitment = setup
                    .commit_row_segment(0, row)
                    .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
                let paired = setup
                    .pair_committed_row(row_index, &row_commitment)
                    .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
                Ok((row_commitment, paired))
            })
            .collect::<Result<Vec<_>, BlsDoryAggregateError>>()?;
        for (local_row, (row_commitment, paired)) in committed_rows.into_iter().enumerate() {
            let row_index = chunk_start + local_row;
            let explicit_in_row = explicit_coefficient_count
                .saturating_sub(row_index * columns)
                .min(columns);
            commitment = commitment + paired;
            row_commitments[row_index] = row_commitment;
            let row_start = local_row * columns;
            writer
                .write_scalars(&coefficients[row_start..row_start + explicit_in_row])
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
        }
    }
    let artifact = writer
        .finish()
        .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
    Ok(BlsDoryCommittedPolynomial {
        coefficients: BlsDoryCoefficientStorage::AuthenticatedArtifact(Arc::new(artifact)),
        commitment,
        row_commitments,
        setup_identity: setup.identity(),
        nu,
        sigma,
    })
}

/// Canonical literal-prefix and one-byte coefficient source backed by a fixed
/// scalar dictionary. Dictionary entry zero must be the field zero; omitted
/// trailing coefficients are represented canonically without entering the
/// artifact.
#[cfg(test)]
pub(crate) trait BlsDoryIndexedRowSource {
    type Error;

    fn rows(&self) -> usize;
    fn columns(&self) -> usize;
    fn explicit_scalar_count(&self) -> usize;
    fn literal_scalar_count(&self) -> usize;
    fn dictionary(&self) -> &[BlsDoryFr];
    fn read_literal_row(
        &mut self,
        row_index: usize,
        output: &mut [BlsDoryFr],
    ) -> Result<usize, Self::Error>;
    fn read_code_row(&mut self, row_index: usize, output: &mut [u8]) -> Result<usize, Self::Error>;
}

/// Canonical fixed-width word prefix plus packed dictionary-code coefficient source.
pub(crate) trait BlsDoryCompactRowSource {
    type Error;

    fn rows(&self) -> usize;
    fn columns(&self) -> usize;
    fn explicit_scalar_count(&self) -> usize;
    fn word_scalar_count(&self) -> usize;
    fn word_bytes(&self) -> u8 {
        8
    }
    fn code_bits(&self) -> u8 {
        8
    }
    fn word_width_codes(&self) -> u64 {
        0
    }
    fn word_group_len(&self) -> usize;
    fn signed_word_selectors(&self) -> u64;
    fn dictionary(&self) -> &[BlsDoryFr];
    fn read_word_row(&mut self, row_index: usize, output: &mut [u64])
    -> Result<usize, Self::Error>;
    fn read_code_row(&mut self, row_index: usize, output: &mut [u8]) -> Result<usize, Self::Error>;
}

/// Commit a canonical indexed row source while retaining literal scalars only
/// for the source-selected row prefix and one authenticated code byte for every
/// remaining explicit coefficient. Expansion is bounded to a row chunk and
/// does not change Dory commitments.
#[cfg(test)]
pub(crate) fn commit_bls_dory_indexed_row_source_with_scratch<S: BlsDoryIndexedRowSource>(
    source: &mut S,
    nu: usize,
    sigma: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<BlsDoryCommittedPolynomial, BlsDoryAggregateError> {
    setup
        .validate()
        .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
    validate_layout(nu, sigma)?;
    let rows = 1usize
        .checked_shl(u32::try_from(nu).map_err(|_| BlsDoryAggregateError::InvalidDimension)?)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let columns = 1usize
        .checked_shl(u32::try_from(sigma).map_err(|_| BlsDoryAggregateError::InvalidDimension)?)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let coefficient_count = rows
        .checked_mul(columns)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let explicit_coefficient_count = source.explicit_scalar_count();
    let literal_coefficient_count = source.literal_scalar_count();
    if source.rows() != rows
        || source.columns() != columns
        || explicit_coefficient_count == 0
        || explicit_coefficient_count > coefficient_count
        || literal_coefficient_count > explicit_coefficient_count
        || !literal_coefficient_count.is_multiple_of(columns)
        || setup.max_log_n() < nu + sigma
        || setup.prover().g1_vec.len() < columns
        || setup.prover().g2_vec.len() < rows
    {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }

    let dictionary = source.dictionary().to_vec();
    let fold_spec = source_artifact_spec(
        setup.identity(),
        nu,
        sigma,
        coefficient_count,
        explicit_coefficient_count,
    )?;
    let index_spec = BlsDoryIndexArtifactSpec {
        context_digest: fold_spec.context_digest,
        scalar_count: fold_spec.scalar_count,
        explicit_scalar_count: fold_spec.explicit_scalar_count,
        literal_scalar_count: u64::try_from(literal_coefficient_count)
            .map_err(|_| BlsDoryAggregateError::InvalidDimension)?,
    };
    let mut writer =
        BlsDoryIndexArtifactWriter::create(scratch_directory, index_spec, dictionary.clone())
            .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
    let mut row_commitments = vec![BlsDoryG1::identity(); rows];
    let mut commitment = BlsDoryGt::identity();
    let explicit_rows = explicit_coefficient_count.div_ceil(columns);
    let literal_rows = literal_coefficient_count / columns;
    let expanded_row_bytes = columns
        .checked_mul(std::mem::size_of::<BlsDoryFr>())
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let rows_per_chunk = (ROW_COMMIT_CHUNK_BYTES / expanded_row_bytes.max(1)).max(1);
    for chunk_start in (0..literal_rows).step_by(rows_per_chunk) {
        let chunk_end = chunk_start.saturating_add(rows_per_chunk).min(literal_rows);
        let chunk_rows = chunk_end - chunk_start;
        let chunk_scalars = chunk_rows
            .checked_mul(columns)
            .ok_or(BlsDoryAggregateError::InvalidDimension)?;
        let mut coefficients = vec![BlsDoryFr::zero(); chunk_scalars];
        for (local_row, row) in coefficients.chunks_exact_mut(columns).enumerate() {
            let row_index = chunk_start + local_row;
            let written = source
                .read_literal_row(row_index, row)
                .map_err(|_| BlsDoryAggregateError::CoefficientSource)?;
            if written != columns {
                return Err(BlsDoryAggregateError::InvalidCoefficientCount);
            }
        }
        let committed_rows = coefficients
            .par_chunks_exact(columns)
            .enumerate()
            .map(|(local_row, row)| {
                let row_index = chunk_start + local_row;
                let row_commitment = setup
                    .commit_row_segment(0, row)
                    .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
                let paired = setup
                    .pair_committed_row(row_index, &row_commitment)
                    .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
                Ok((row_commitment, paired))
            })
            .collect::<Result<Vec<_>, BlsDoryAggregateError>>()?;
        for (local_row, (row_commitment, paired)) in committed_rows.into_iter().enumerate() {
            let row_index = chunk_start + local_row;
            commitment = commitment + paired;
            row_commitments[row_index] = row_commitment;
            let row_start = local_row * columns;
            writer
                .write_scalars(&coefficients[row_start..row_start + columns])
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
        }
    }
    for chunk_start in (literal_rows..explicit_rows).step_by(rows_per_chunk) {
        let chunk_end = chunk_start
            .saturating_add(rows_per_chunk)
            .min(explicit_rows);
        let chunk_rows = chunk_end - chunk_start;
        let chunk_codes = chunk_rows
            .checked_mul(columns)
            .ok_or(BlsDoryAggregateError::InvalidDimension)?;
        let mut codes = vec![0u8; chunk_codes];
        for (local_row, row) in codes.chunks_exact_mut(columns).enumerate() {
            let row_index = chunk_start + local_row;
            let written = source
                .read_code_row(row_index, row)
                .map_err(|_| BlsDoryAggregateError::CoefficientSource)?;
            if written != columns {
                return Err(BlsDoryAggregateError::InvalidCoefficientCount);
            }
            let explicit_in_row = explicit_coefficient_count
                .saturating_sub(row_index * columns)
                .min(columns);
            row[explicit_in_row..].fill(0);
        }
        if codes
            .iter()
            .any(|code| usize::from(*code) >= dictionary.len())
        {
            return Err(BlsDoryAggregateError::CoefficientSource);
        }
        let committed_rows = codes
            .par_chunks_exact(columns)
            .enumerate()
            .map(|(local_row, row)| {
                let row_index = chunk_start + local_row;
                let coefficients = row
                    .iter()
                    .map(|code| dictionary[usize::from(*code)])
                    .collect::<Vec<_>>();
                let row_commitment = setup
                    .commit_row_segment(0, &coefficients)
                    .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
                let paired = setup
                    .pair_committed_row(row_index, &row_commitment)
                    .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
                Ok((row_commitment, paired))
            })
            .collect::<Result<Vec<_>, BlsDoryAggregateError>>()?;
        for (local_row, (row_commitment, paired)) in committed_rows.into_iter().enumerate() {
            let row_index = chunk_start + local_row;
            let explicit_in_row = explicit_coefficient_count
                .saturating_sub(row_index * columns)
                .min(columns);
            commitment = commitment + paired;
            row_commitments[row_index] = row_commitment;
            let row_start = local_row * columns;
            writer
                .write_codes(&codes[row_start..row_start + explicit_in_row])
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
        }
    }
    let artifact = writer
        .finish()
        .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
    Ok(BlsDoryCommittedPolynomial {
        coefficients: BlsDoryCoefficientStorage::IndexedArtifact(Arc::new(artifact)),
        commitment,
        row_commitments,
        setup_identity: setup.identity(),
        nu,
        sigma,
    })
}

/// Commit a mixed-width source while retaining regular coefficients as
/// canonical signed/unsigned words and its remaining coefficients as codes.
pub(crate) fn commit_bls_dory_compact_row_source_with_scratch<S: BlsDoryCompactRowSource>(
    source: &mut S,
    nu: usize,
    sigma: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<BlsDoryCommittedPolynomial, BlsDoryAggregateError> {
    setup
        .validate()
        .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
    validate_layout(nu, sigma)?;
    let rows = 1usize
        .checked_shl(u32::try_from(nu).map_err(|_| BlsDoryAggregateError::InvalidDimension)?)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let columns = 1usize
        .checked_shl(u32::try_from(sigma).map_err(|_| BlsDoryAggregateError::InvalidDimension)?)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let coefficient_count = rows
        .checked_mul(columns)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let explicit_coefficient_count = source.explicit_scalar_count();
    let word_coefficient_count = source.word_scalar_count();
    let word_bytes = source.word_bytes();
    let code_bits = source.code_bits();
    let word_width_codes = source.word_width_codes();
    let word_group_len = source.word_group_len();
    let signed_word_selectors = source.signed_word_selectors();
    if source.rows() != rows
        || source.columns() != columns
        || explicit_coefficient_count == 0
        || explicit_coefficient_count > coefficient_count
        || word_coefficient_count > explicit_coefficient_count
        || !matches!(word_bytes, 4 | 8)
        || !matches!(code_bits, 4 | 8)
        || !word_coefficient_count.is_multiple_of(columns)
        || word_group_len == 0
        || !word_group_len.is_power_of_two()
        || !word_coefficient_count.is_multiple_of(word_group_len)
        || setup.max_log_n() < nu + sigma
        || setup.prover().g1_vec.len() < columns
        || setup.prover().g2_vec.len() < rows
    {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }

    let dictionary = source.dictionary().to_vec();
    let fold_spec = source_artifact_spec(
        setup.identity(),
        nu,
        sigma,
        coefficient_count,
        explicit_coefficient_count,
    )?;
    let compact_spec = BlsDoryCompactArtifactSpec {
        context_digest: fold_spec.context_digest,
        scalar_count: fold_spec.scalar_count,
        explicit_scalar_count: fold_spec.explicit_scalar_count,
        word_scalar_count: u64::try_from(word_coefficient_count)
            .map_err(|_| BlsDoryAggregateError::InvalidDimension)?,
        word_bytes,
        code_bits,
        word_width_codes,
        word_group_len: u64::try_from(word_group_len)
            .map_err(|_| BlsDoryAggregateError::InvalidDimension)?,
        signed_word_selectors,
    };
    let mut writer =
        BlsDoryCompactArtifactWriter::create(scratch_directory, compact_spec, dictionary.clone())
            .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
    let mut row_commitments = vec![BlsDoryG1::identity(); rows];
    let mut commitment = BlsDoryGt::identity();
    let explicit_rows = explicit_coefficient_count.div_ceil(columns);
    let word_rows = word_coefficient_count / columns;
    let expanded_row_bytes = columns
        .checked_mul(std::mem::size_of::<BlsDoryFr>())
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let rows_per_chunk = (ROW_COMMIT_CHUNK_BYTES / expanded_row_bytes.max(1)).max(1);
    for chunk_start in (0..word_rows).step_by(rows_per_chunk) {
        let chunk_end = chunk_start.saturating_add(rows_per_chunk).min(word_rows);
        let chunk_rows = chunk_end - chunk_start;
        let chunk_words = chunk_rows
            .checked_mul(columns)
            .ok_or(BlsDoryAggregateError::InvalidDimension)?;
        let mut words = vec![0u64; chunk_words];
        for (local_row, row) in words.chunks_exact_mut(columns).enumerate() {
            let written = source
                .read_word_row(chunk_start + local_row, row)
                .map_err(|_| BlsDoryAggregateError::CoefficientSource)?;
            if written != columns {
                return Err(BlsDoryAggregateError::InvalidCoefficientCount);
            }
        }
        let committed_rows = words
            .par_chunks_exact(columns)
            .enumerate()
            .map(|(local_row, row)| {
                let row_index = chunk_start + local_row;
                let packed_start = row_index
                    .checked_mul(columns)
                    .ok_or(BlsDoryAggregateError::InvalidDimension)?;
                let coefficients = row
                    .iter()
                    .copied()
                    .enumerate()
                    .map(|(column, word)| {
                        compact_word_scalar(
                            word,
                            packed_start + column,
                            word_group_len,
                            signed_word_selectors,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let row_commitment = setup
                    .commit_row_segment(0, &coefficients)
                    .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
                let paired = setup
                    .pair_committed_row(row_index, &row_commitment)
                    .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
                Ok((row_commitment, paired))
            })
            .collect::<Result<Vec<_>, BlsDoryAggregateError>>()?;
        for (local_row, (row_commitment, paired)) in committed_rows.into_iter().enumerate() {
            let row_index = chunk_start + local_row;
            commitment = commitment + paired;
            row_commitments[row_index] = row_commitment;
            let row_start = local_row * columns;
            writer
                .write_words(&words[row_start..row_start + columns])
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
        }
    }
    for chunk_start in (word_rows..explicit_rows).step_by(rows_per_chunk) {
        let chunk_end = chunk_start
            .saturating_add(rows_per_chunk)
            .min(explicit_rows);
        let chunk_rows = chunk_end - chunk_start;
        let chunk_codes = chunk_rows
            .checked_mul(columns)
            .ok_or(BlsDoryAggregateError::InvalidDimension)?;
        let mut codes = vec![0u8; chunk_codes];
        for (local_row, row) in codes.chunks_exact_mut(columns).enumerate() {
            let row_index = chunk_start + local_row;
            let written = source
                .read_code_row(row_index, row)
                .map_err(|_| BlsDoryAggregateError::CoefficientSource)?;
            if written != columns {
                return Err(BlsDoryAggregateError::InvalidCoefficientCount);
            }
            let explicit_in_row = explicit_coefficient_count
                .saturating_sub(row_index * columns)
                .min(columns);
            row[explicit_in_row..].fill(0);
        }
        if codes
            .iter()
            .any(|code| usize::from(*code) >= dictionary.len())
        {
            return Err(BlsDoryAggregateError::CoefficientSource);
        }
        let committed_rows = codes
            .par_chunks_exact(columns)
            .enumerate()
            .map(|(local_row, row)| {
                let row_index = chunk_start + local_row;
                let coefficients = row
                    .iter()
                    .map(|code| dictionary[usize::from(*code)])
                    .collect::<Vec<_>>();
                let row_commitment = setup
                    .commit_row_segment(0, &coefficients)
                    .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
                let paired = setup
                    .pair_committed_row(row_index, &row_commitment)
                    .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
                Ok((row_commitment, paired))
            })
            .collect::<Result<Vec<_>, BlsDoryAggregateError>>()?;
        for (local_row, (row_commitment, paired)) in committed_rows.into_iter().enumerate() {
            let row_index = chunk_start + local_row;
            let explicit_in_row = explicit_coefficient_count
                .saturating_sub(row_index * columns)
                .min(columns);
            commitment = commitment + paired;
            row_commitments[row_index] = row_commitment;
            let row_start = local_row * columns;
            writer
                .write_codes(&codes[row_start..row_start + explicit_in_row])
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
        }
    }
    let artifact = writer
        .finish()
        .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
    Ok(BlsDoryCommittedPolynomial {
        coefficients: BlsDoryCoefficientStorage::CompactArtifact(Arc::new(artifact)),
        commitment,
        row_commitments,
        setup_identity: setup.identity(),
        nu,
        sigma,
    })
}

/// Commit an already-finished compact coefficient artifact without creating a
/// second coefficient file. The artifact's source context binds its setup and
/// matrix layout; its complete live file is authenticated while coefficients
/// are decoded into bounded row chunks.
pub(crate) fn commit_bls_dory_existing_compact_artifact(
    artifact: Arc<BlsDoryCompactArtifact>,
    nu: usize,
    sigma: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryCommittedPolynomial, BlsDoryAggregateError> {
    setup
        .validate()
        .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
    validate_layout(nu, sigma)?;
    let rows = 1usize
        .checked_shl(u32::try_from(nu).map_err(|_| BlsDoryAggregateError::InvalidDimension)?)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let columns = 1usize
        .checked_shl(u32::try_from(sigma).map_err(|_| BlsDoryAggregateError::InvalidDimension)?)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let coefficient_count = rows
        .checked_mul(columns)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let spec = artifact.spec();
    let explicit_coefficient_count = usize::try_from(spec.explicit_scalar_count)
        .map_err(|_| BlsDoryAggregateError::InvalidDimension)?;
    let word_coefficient_count = usize::try_from(spec.word_scalar_count)
        .map_err(|_| BlsDoryAggregateError::InvalidDimension)?;
    let expected = source_artifact_spec(
        setup.identity(),
        nu,
        sigma,
        coefficient_count,
        explicit_coefficient_count,
    )?;
    if spec.encoded_bytes(artifact.dictionary().len()).is_err()
        || spec.context_digest != expected.context_digest
        || spec.scalar_count != expected.scalar_count
        || spec.explicit_scalar_count != expected.explicit_scalar_count
        || explicit_coefficient_count == 0
        || explicit_coefficient_count > coefficient_count
        || word_coefficient_count > explicit_coefficient_count
        || !word_coefficient_count.is_multiple_of(columns)
        || setup.max_log_n() < nu + sigma
        || setup.prover().g1_vec.len() < columns
        || setup.prover().g2_vec.len() < rows
    {
        return Err(BlsDoryAggregateError::ProverStorage);
    }

    let expanded_row_bytes = columns
        .checked_mul(std::mem::size_of::<BlsDoryFr>())
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    if expanded_row_bytes > ROW_COMMIT_CHUNK_BYTES {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }
    let rows_per_chunk = (ROW_COMMIT_CHUNK_BYTES / expanded_row_bytes.max(1)).max(1);
    let chunk_scalars = rows_per_chunk
        .checked_mul(columns)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let pending_capacity = chunk_scalars.min(explicit_coefficient_count);
    let mut pending = Vec::new();
    pending
        .try_reserve_exact(pending_capacity)
        .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
    let explicit_rows = explicit_coefficient_count.div_ceil(columns);
    let mut row_commitments = vec![BlsDoryG1::identity(); rows];
    let mut commitment = BlsDoryGt::identity();
    let mut committed_rows = 0usize;
    let mut decoded_count = 0usize;
    {
        let mut commit_chunk = |coefficients: &[BlsDoryFr]| -> Result<(), BlsDoryAggregateError> {
            if coefficients.is_empty() || !coefficients.len().is_multiple_of(columns) {
                return Err(BlsDoryAggregateError::InvalidCoefficientCount);
            }
            let chunk_rows = coefficients.len() / columns;
            let chunk_end = committed_rows
                .checked_add(chunk_rows)
                .ok_or(BlsDoryAggregateError::InvalidDimension)?;
            if chunk_end > explicit_rows {
                return Err(BlsDoryAggregateError::InvalidCoefficientCount);
            }
            let committed = coefficients
                .par_chunks_exact(columns)
                .enumerate()
                .map(|(local_row, row)| {
                    let row_index = committed_rows
                        .checked_add(local_row)
                        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
                    let row_commitment = setup
                        .commit_row_segment(0, row)
                        .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
                    let paired = setup
                        .pair_committed_row(row_index, &row_commitment)
                        .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
                    Ok((row_commitment, paired))
                })
                .collect::<Result<Vec<_>, BlsDoryAggregateError>>()?;
            for (local_row, (row_commitment, paired)) in committed.into_iter().enumerate() {
                row_commitments[committed_rows + local_row] = row_commitment;
                commitment = commitment + paired;
            }
            committed_rows = chunk_end;
            Ok(())
        };
        let mut commit_error = None;
        let authentication = artifact.for_each_scalar(|coefficient| {
            decoded_count = decoded_count
                .checked_add(1)
                .ok_or(BlsDoryCompactArtifactError::InvalidArtifact)?;
            pending.push(coefficient);
            if pending.len() == chunk_scalars {
                if let Err(error) = commit_chunk(&pending) {
                    commit_error = Some(error);
                    return Err(BlsDoryCompactArtifactError::InvalidArtifact);
                }
                pending.clear();
            }
            Ok(())
        });
        if let Some(error) = commit_error.take() {
            return Err(error);
        }
        authentication.map_err(|_| BlsDoryAggregateError::ProverStorage)?;
        if decoded_count != explicit_coefficient_count {
            return Err(BlsDoryAggregateError::ProverStorage);
        }
        if !pending.is_empty() {
            let padded_len = pending
                .len()
                .div_ceil(columns)
                .checked_mul(columns)
                .ok_or(BlsDoryAggregateError::InvalidDimension)?;
            if padded_len > chunk_scalars {
                return Err(BlsDoryAggregateError::InvalidDimension);
            }
            pending
                .try_reserve_exact(padded_len - pending.len())
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
            pending.resize(padded_len, BlsDoryFr::zero());
            commit_chunk(&pending)?;
        }
    }
    if committed_rows != explicit_rows {
        return Err(BlsDoryAggregateError::InvalidCoefficientCount);
    }

    Ok(BlsDoryCommittedPolynomial {
        coefficients: BlsDoryCoefficientStorage::CompactArtifact(artifact),
        commitment,
        row_commitments,
        setup_identity: setup.identity(),
        nu,
        sigma,
    })
}

/// Regenerate only the authenticated compact coefficient file for a committed
/// source that was deliberately released between component proving and shared
/// aggregation. Existing Dory commitments are never recomputed or trusted
/// against a new witness: the complete regenerated artifact must match the
/// independently retained source identity byte-for-byte through its digest.
pub(crate) fn regenerate_bls_dory_compact_row_source_with_scratch<S: BlsDoryCompactRowSource>(
    source: &mut S,
    expected: &BlsDoryReleasedCompactSource,
    nu: usize,
    sigma: usize,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<Arc<BlsDoryCompactArtifact>, BlsDoryAggregateError> {
    setup
        .validate()
        .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
    validate_layout(nu, sigma)?;
    let rows = 1usize
        .checked_shl(u32::try_from(nu).map_err(|_| BlsDoryAggregateError::InvalidDimension)?)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let columns = 1usize
        .checked_shl(u32::try_from(sigma).map_err(|_| BlsDoryAggregateError::InvalidDimension)?)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let coefficient_count = rows
        .checked_mul(columns)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let explicit_coefficient_count = source.explicit_scalar_count();
    let word_coefficient_count = source.word_scalar_count();
    let word_bytes = source.word_bytes();
    let code_bits = source.code_bits();
    let word_width_codes = source.word_width_codes();
    let word_group_len = source.word_group_len();
    let signed_word_selectors = source.signed_word_selectors();
    if source.rows() != rows
        || source.columns() != columns
        || explicit_coefficient_count == 0
        || explicit_coefficient_count > coefficient_count
        || word_coefficient_count > explicit_coefficient_count
        || !matches!(word_bytes, 4 | 8)
        || !matches!(code_bits, 4 | 8)
        || !word_coefficient_count.is_multiple_of(columns)
        || word_group_len == 0
        || !word_group_len.is_power_of_two()
        || !word_coefficient_count.is_multiple_of(word_group_len)
        || setup.max_log_n() < nu + sigma
    {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }
    let dictionary = source.dictionary().to_vec();
    let fold_spec = source_artifact_spec(
        setup.identity(),
        nu,
        sigma,
        coefficient_count,
        explicit_coefficient_count,
    )?;
    let compact_spec = BlsDoryCompactArtifactSpec {
        context_digest: fold_spec.context_digest,
        scalar_count: fold_spec.scalar_count,
        explicit_scalar_count: fold_spec.explicit_scalar_count,
        word_scalar_count: u64::try_from(word_coefficient_count)
            .map_err(|_| BlsDoryAggregateError::InvalidDimension)?,
        word_bytes,
        code_bits,
        word_width_codes,
        word_group_len: u64::try_from(word_group_len)
            .map_err(|_| BlsDoryAggregateError::InvalidDimension)?,
        signed_word_selectors,
    };
    if compact_spec != expected.spec || dictionary != expected.dictionary {
        return Err(BlsDoryAggregateError::ProverStorage);
    }
    let mut writer =
        BlsDoryCompactArtifactWriter::create(scratch_directory, compact_spec, dictionary.clone())
            .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
    let word_rows = word_coefficient_count / columns;
    let explicit_rows = explicit_coefficient_count.div_ceil(columns);
    let mut words = vec![0u64; columns];
    for row_index in 0..word_rows {
        let written = source
            .read_word_row(row_index, &mut words)
            .map_err(|_| BlsDoryAggregateError::CoefficientSource)?;
        if written != columns {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        writer
            .write_words(&words)
            .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
    }
    let mut codes = vec![0u8; columns];
    for row_index in word_rows..explicit_rows {
        let written = source
            .read_code_row(row_index, &mut codes)
            .map_err(|_| BlsDoryAggregateError::CoefficientSource)?;
        if written != columns {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        let explicit_in_row = explicit_coefficient_count
            .saturating_sub(row_index * columns)
            .min(columns);
        codes[explicit_in_row..].fill(0);
        if codes[..explicit_in_row]
            .iter()
            .any(|code| usize::from(*code) >= dictionary.len())
        {
            return Err(BlsDoryAggregateError::CoefficientSource);
        }
        writer
            .write_codes(&codes[..explicit_in_row])
            .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
    }
    let artifact = writer
        .finish()
        .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
    expected.validate_artifact(&artifact)?;
    Ok(Arc::new(artifact))
}

/// Commit a deterministic scalar mapping of an authenticated compact source
/// while retaining only a shared view of the source file. This is used for the
/// LogUp inverse, whose codes are exactly the transition's radix-16 digits.
pub(crate) fn commit_bls_dory_mapped_compact_polynomial(
    source: &BlsDoryCommittedPolynomial,
    zero_prefix_count: usize,
    mapped_dictionary: Vec<BlsDoryFr>,
    setup: &DeterministicBlsDorySetup,
) -> Result<BlsDoryCommittedPolynomial, BlsDoryAggregateError> {
    setup
        .validate()
        .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
    validate_layout(source.nu, source.sigma)?;
    if source.setup_identity != setup.identity()
        || setup.max_log_n() < source.variables()
        || zero_prefix_count == 0
        || zero_prefix_count >= source.explicit_coefficient_count()
    {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }
    let compact = match &source.coefficients {
        BlsDoryCoefficientStorage::CompactArtifact(artifact) => Arc::clone(artifact),
        _ => return Err(BlsDoryAggregateError::CoefficientSource),
    };
    let mapped = Arc::new(
        BlsDoryMappedCompactArtifact::new(
            compact,
            u64::try_from(zero_prefix_count)
                .map_err(|_| BlsDoryAggregateError::InvalidDimension)?,
            mapped_dictionary,
        )
        .map_err(|_| BlsDoryAggregateError::CoefficientSource)?,
    );
    let rows = 1usize
        .checked_shl(u32::try_from(source.nu).map_err(|_| BlsDoryAggregateError::InvalidDimension)?)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let columns = 1usize
        .checked_shl(
            u32::try_from(source.sigma).map_err(|_| BlsDoryAggregateError::InvalidDimension)?,
        )
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    if mapped.scalar_count() as usize != rows * columns
        || mapped.explicit_scalar_count() as usize != source.explicit_coefficient_count()
        || setup.prover().g1_vec.len() < columns
        || setup.prover().g2_vec.len() < rows
    {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }
    let row_bytes = columns
        .checked_mul(std::mem::size_of::<BlsDoryFr>())
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let rows_per_chunk = (ROW_COMMIT_CHUNK_BYTES / row_bytes.max(1)).max(1);
    let chunk_scalars = rows_per_chunk
        .checked_mul(columns)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let explicit_rows = source.explicit_coefficient_count().div_ceil(columns);
    let mut row_commitments = vec![BlsDoryG1::identity(); rows];
    let mut commitment = BlsDoryGt::identity();
    let mut committed_rows = 0usize;
    let mut commit_error = None;
    let mapping_result = mapped.for_each_chunk(chunk_scalars, |chunk| {
        let result = (|| -> Result<(), BlsDoryAggregateError> {
            let chunk_rows = chunk.len().div_ceil(columns);
            let mut padded = Vec::new();
            let coefficients = if chunk.len().is_multiple_of(columns) {
                chunk
            } else {
                padded.extend_from_slice(chunk);
                padded.resize(chunk_rows * columns, BlsDoryFr::zero());
                &padded
            };
            let batch = coefficients
                .par_chunks_exact(columns)
                .enumerate()
                .map(|(local_row, row)| {
                    let row_index = committed_rows
                        .checked_add(local_row)
                        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
                    let row_commitment = setup
                        .commit_row_segment(0, row)
                        .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
                    let paired = setup
                        .pair_committed_row(row_index, &row_commitment)
                        .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
                    Ok((row_commitment, paired))
                })
                .collect::<Result<Vec<_>, BlsDoryAggregateError>>()?;
            for (local_row, (row_commitment, paired)) in batch.into_iter().enumerate() {
                let row_index = committed_rows + local_row;
                commitment = commitment + paired;
                row_commitments[row_index] = row_commitment;
            }
            committed_rows = committed_rows
                .checked_add(chunk_rows)
                .ok_or(BlsDoryAggregateError::InvalidDimension)?;
            Ok(())
        })();
        if let Err(error) = result {
            commit_error = Some(error);
            return Err(BlsDoryCompactArtifactError::InvalidArtifact);
        }
        Ok(())
    });
    if let Some(error) = commit_error {
        return Err(error);
    }
    mapping_result.map_err(|_| BlsDoryAggregateError::ProverStorage)?;
    if committed_rows != explicit_rows {
        return Err(BlsDoryAggregateError::InvalidCoefficientCount);
    }
    Ok(BlsDoryCommittedPolynomial {
        coefficients: BlsDoryCoefficientStorage::MappedCompactArtifact(mapped),
        commitment,
        row_commitments,
        setup_identity: setup.identity(),
        nu: source.nu,
        sigma: source.sigma,
    })
}

fn compact_word_scalar(
    word: u64,
    packed_index: usize,
    word_group_len: usize,
    signed_word_selectors: u64,
) -> Result<BlsDoryFr, BlsDoryAggregateError> {
    let selector = packed_index
        .checked_div(word_group_len)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let signed = compact_selector_is_signed(selector, signed_word_selectors);
    if signed {
        Ok(BlsDoryFr::from_i64(i64::from_le_bytes(word.to_le_bytes())))
    } else {
        Ok(BlsDoryFr::from_u64(word))
    }
}

fn compact_selector_is_signed(selector: usize, signed_word_selectors: u64) -> bool {
    if selector < 64 {
        signed_word_selectors & (1u64 << selector) != 0
    } else {
        signed_word_selectors == u64::MAX
    }
}

pub(crate) fn source_artifact_spec(
    setup_identity: [u8; 32],
    nu: usize,
    sigma: usize,
    coefficient_count: usize,
    explicit_coefficient_count: usize,
) -> Result<BlsDoryFoldArtifactSpec, BlsDoryAggregateError> {
    let nu = u64::try_from(nu).map_err(|_| BlsDoryAggregateError::InvalidDimension)?;
    let sigma = u64::try_from(sigma).map_err(|_| BlsDoryAggregateError::InvalidDimension)?;
    let scalar_count =
        u64::try_from(coefficient_count).map_err(|_| BlsDoryAggregateError::InvalidDimension)?;
    let explicit_scalar_count = u64::try_from(explicit_coefficient_count)
        .map_err(|_| BlsDoryAggregateError::InvalidDimension)?;
    let mut context =
        blake3::Hasher::new_derive_key("CommonFoundry/ForgeMatrix/BlsDorySourceContext/v1");
    context.update(&setup_identity);
    context.update(&nu.to_le_bytes());
    context.update(&sigma.to_le_bytes());
    context.update(&scalar_count.to_le_bytes());
    context.update(&explicit_scalar_count.to_le_bytes());
    let context_digest = *context.finalize().as_bytes();
    let mut parent =
        blake3::Hasher::new_derive_key("CommonFoundry/ForgeMatrix/BlsDorySourceParent/v1");
    parent.update(&context_digest);
    let parent_digest = *parent.finalize().as_bytes();
    if context_digest == [0; 32] || parent_digest == [0; 32] {
        return Err(BlsDoryAggregateError::ProverStorage);
    }
    Ok(BlsDoryFoldArtifactSpec {
        context_digest,
        table_index: 0,
        generation: 1,
        scalar_count,
        explicit_scalar_count,
        parent_digest,
    })
}

/// Reduce distinct-point claims to one random point and prove one combined opening.
pub fn prove_bls_dory_openings(
    public_binding: &[u8],
    layout: BlsDoryAggregateLayout,
    polynomials: &[BlsDoryCommittedPolynomial],
    points: &[Vec<BlsDoryFr>],
    setup: &DeterministicBlsDorySetup,
) -> Result<(Vec<BlsDoryOpeningClaim>, Vec<u8>), BlsDoryAggregateError> {
    let polynomial_refs = polynomials.iter().collect::<Vec<_>>();
    prove_bls_dory_opening_refs_with_scratch(
        public_binding,
        layout,
        &polynomial_refs,
        points,
        setup,
        None,
    )
}

/// Prove the same aggregate while keeping every post-challenge polynomial fold
/// in self-authenticating scratch files.
///
/// Storage metadata is prover-local and does not alter the proof transcript.
/// Any scratch failure aborts without retrying through the in-memory path.
pub fn prove_bls_dory_openings_with_scratch(
    public_binding: &[u8],
    layout: BlsDoryAggregateLayout,
    polynomials: &[BlsDoryCommittedPolynomial],
    points: &[Vec<BlsDoryFr>],
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<(Vec<BlsDoryOpeningClaim>, Vec<u8>), BlsDoryAggregateError> {
    let polynomial_refs = polynomials.iter().collect::<Vec<_>>();
    prove_bls_dory_opening_refs_with_scratch(
        public_binding,
        layout,
        &polynomial_refs,
        points,
        setup,
        Some(scratch_directory),
    )
}

/// Prove many points of one commitment without cloning its coefficient table.
pub fn prove_bls_dory_same_commitment_openings(
    public_binding: &[u8],
    layout: BlsDoryAggregateLayout,
    polynomial: &BlsDoryCommittedPolynomial,
    points: &[Vec<BlsDoryFr>],
    setup: &DeterministicBlsDorySetup,
) -> Result<(Vec<BlsDoryOpeningClaim>, Vec<u8>), BlsDoryAggregateError> {
    let polynomial_refs = vec![polynomial; points.len()];
    prove_bls_dory_opening_refs_with_scratch(
        public_binding,
        layout,
        &polynomial_refs,
        points,
        setup,
        None,
    )
}

#[cfg(test)]
fn prove_bls_dory_same_commitment_openings_with_test_claim_limit(
    public_binding: &[u8],
    layout: BlsDoryAggregateLayout,
    polynomial: &BlsDoryCommittedPolynomial,
    points: &[Vec<BlsDoryFr>],
    setup: &DeterministicBlsDorySetup,
) -> Result<(Vec<BlsDoryOpeningClaim>, Vec<u8>), BlsDoryAggregateError> {
    let polynomial_refs = vec![polynomial; points.len()];
    let prepared = prepare_bls_dory_opening_refs_with_claim_limit(
        public_binding,
        layout,
        &polynomial_refs,
        points,
        setup,
        None,
        BLS_DORY_COMPOSED_AGGREGATE_CLAIMS,
    )?;
    finish_prepared_bls_dory_opening(prepared, setup)
}

struct PreparedBlsDoryOpeningProof {
    claims: Vec<BlsDoryOpeningClaim>,
    transcript: BlsDoryTranscript,
    sumcheck_rounds: Vec<[BlsDoryFr; 3]>,
    random_point: Vec<BlsDoryFr>,
    combined_rows: Vec<BlsDoryG1>,
    vector_matrix_product: Vec<BlsDoryFr>,
    variables: usize,
    nu: usize,
    sigma: usize,
}

fn prove_bls_dory_opening_refs_with_scratch(
    public_binding: &[u8],
    layout: BlsDoryAggregateLayout,
    polynomials: &[&BlsDoryCommittedPolynomial],
    points: &[Vec<BlsDoryFr>],
    setup: &DeterministicBlsDorySetup,
    scratch_directory: Option<&Path>,
) -> Result<(Vec<BlsDoryOpeningClaim>, Vec<u8>), BlsDoryAggregateError> {
    let prepared = prepare_bls_dory_opening_refs(
        public_binding,
        layout,
        polynomials,
        points,
        setup,
        scratch_directory,
    )?;
    finish_prepared_bls_dory_opening(prepared, setup)
}

fn prepare_bls_dory_opening_refs(
    public_binding: &[u8],
    layout: BlsDoryAggregateLayout,
    polynomials: &[&BlsDoryCommittedPolynomial],
    points: &[Vec<BlsDoryFr>],
    setup: &DeterministicBlsDorySetup,
    scratch_directory: Option<&Path>,
) -> Result<PreparedBlsDoryOpeningProof, BlsDoryAggregateError> {
    prepare_bls_dory_opening_refs_with_claim_limit(
        public_binding,
        layout,
        polynomials,
        points,
        setup,
        scratch_directory,
        MAX_BLS_DORY_AGGREGATE_CLAIMS,
    )
}

fn prepare_bls_dory_opening_refs_with_claim_limit(
    public_binding: &[u8],
    layout: BlsDoryAggregateLayout,
    polynomials: &[&BlsDoryCommittedPolynomial],
    points: &[Vec<BlsDoryFr>],
    setup: &DeterministicBlsDorySetup,
    scratch_directory: Option<&Path>,
    maximum_claims: usize,
) -> Result<PreparedBlsDoryOpeningProof, BlsDoryAggregateError> {
    validate_public_inputs_with_claim_limit(public_binding, polynomials.len(), maximum_claims)?;
    setup
        .validate()
        .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
    if polynomials.len() != points.len() {
        return Err(BlsDoryAggregateError::InvalidClaimCount);
    }
    let (nu, sigma) = (layout.nu, layout.sigma);
    let variables = layout.variables();
    if setup.max_log_n() < variables
        || polynomials.iter().any(|polynomial| {
            polynomial.nu != nu
                || polynomial.sigma != sigma
                || polynomial.setup_identity != setup.identity()
        })
    {
        return Err(BlsDoryAggregateError::MixedStatement);
    }
    if points.iter().any(|point| point.len() != variables) {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }

    let claims = polynomials
        .iter()
        .zip(points)
        .map(|(polynomial, point)| {
            Ok(BlsDoryOpeningClaim {
                commitment: polynomial.commitment,
                point: point.clone(),
                evaluation: polynomial.evaluate(point)?,
            })
        })
        .collect::<Result<Vec<_>, BlsDoryAggregateError>>()?;
    let mut transcript =
        statement_transcript(public_binding, &setup.identity(), &claims, nu, sigma)?;
    let batching = batching_challenges(&mut transcript, claims.len());
    let scratch = scratch_directory
        .map(|directory| FoldScratch::new(directory, transcript.digest()))
        .transpose()?;
    let sumcheck = prove_distinct_point_sumcheck(
        polynomials,
        &claims,
        &batching,
        &mut transcript,
        scratch.as_ref(),
    )?;

    let SumcheckProverOutput {
        rounds: sumcheck_rounds,
        terminal,
        ..
    } = sumcheck;
    let SumcheckTerminal {
        random_point,
        final_claim,
        equality_values,
    } = terminal;
    let lambdas = batching
        .iter()
        .zip(&equality_values)
        .map(|(rho, equality)| *rho * equality)
        .collect::<Vec<_>>();
    let (combined_rows, combined_commitment, vector_matrix_product) =
        combine_polynomials_for_opening(polynomials, &lambdas, &random_point, nu, sigma)?;

    append_combined_opening(
        &mut transcript,
        &combined_commitment,
        &random_point,
        &final_claim,
    );
    Ok(PreparedBlsDoryOpeningProof {
        claims,
        transcript,
        sumcheck_rounds,
        random_point,
        combined_rows,
        vector_matrix_product,
        variables,
        nu,
        sigma,
    })
}

fn finish_prepared_bls_dory_opening(
    prepared: PreparedBlsDoryOpeningProof,
    setup: &DeterministicBlsDorySetup,
) -> Result<(Vec<BlsDoryOpeningClaim>, Vec<u8>), BlsDoryAggregateError> {
    let PreparedBlsDoryOpeningProof {
        claims,
        mut transcript,
        sumcheck_rounds,
        random_point,
        combined_rows,
        vector_matrix_product,
        variables,
        nu,
        sigma,
    } = prepared;
    let dory_proof = prove_bls_dory_opening_from_vector_product(
        &random_point,
        combined_rows,
        vector_matrix_product,
        nu,
        sigma,
        setup,
        &mut transcript,
    )
    .map_err(|error| BlsDoryAggregateError::Dory(error.to_string()))?;

    let encoded = encode_aggregate_proof(
        claims.len(),
        variables,
        nu,
        sigma,
        &sumcheck_rounds,
        &dory_proof,
    )?;
    Ok((claims, encoded))
}

/// Prove several component opening sets with one aggregate transcript and one
/// Dory payload.
pub(crate) fn prove_bls_dory_deferred_opening_sets(
    public_binding: &[u8],
    layout: BlsDoryAggregateLayout,
    sets: &[&BlsDoryDeferredOpeningSet],
    setup: &DeterministicBlsDorySetup,
) -> Result<(Vec<BlsDoryOpeningClaim>, Vec<u8>), BlsDoryAggregateError> {
    prove_bls_dory_deferred_opening_sets_with_optional_scratch(
        public_binding,
        layout,
        sets,
        setup,
        None,
    )
}

#[cfg(test)]
pub(crate) fn prove_bls_dory_deferred_opening_sets_with_scratch(
    public_binding: &[u8],
    layout: BlsDoryAggregateLayout,
    sets: &[&BlsDoryDeferredOpeningSet],
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<(Vec<BlsDoryOpeningClaim>, Vec<u8>), BlsDoryAggregateError> {
    prove_bls_dory_deferred_opening_sets_with_optional_scratch(
        public_binding,
        layout,
        sets,
        setup,
        Some(scratch_directory),
    )
}

pub(crate) fn prove_bls_dory_deferred_opening_sets_consuming(
    public_binding: &[u8],
    layout: BlsDoryAggregateLayout,
    sets: Vec<BlsDoryDeferredOpeningSet>,
    setup: &DeterministicBlsDorySetup,
) -> Result<(Vec<BlsDoryOpeningClaim>, Vec<u8>), BlsDoryAggregateError> {
    prove_bls_dory_deferred_opening_sets_consuming_with_optional_scratch(
        public_binding,
        layout,
        sets,
        setup,
        None,
        MAX_BLS_DORY_AGGREGATE_CLAIMS,
    )
}

pub(crate) fn prove_bls_dory_deferred_opening_sets_consuming_with_scratch(
    public_binding: &[u8],
    layout: BlsDoryAggregateLayout,
    sets: Vec<BlsDoryDeferredOpeningSet>,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<(Vec<BlsDoryOpeningClaim>, Vec<u8>), BlsDoryAggregateError> {
    prove_bls_dory_deferred_opening_sets_consuming_with_optional_scratch(
        public_binding,
        layout,
        sets,
        setup,
        Some(scratch_directory),
        MAX_BLS_DORY_AGGREGATE_CLAIMS,
    )
}

/// Consume exactly the shared-128 plus native-BLAKE3-6 opening partition.
/// This specialized seam does not widen the generic public claim cap.
#[cfg(any(test, feature = "whir-prototype"))]
pub(crate) fn prove_bls_dory_deferred_opening_sets_consuming_composed(
    public_binding: &[u8],
    layout: BlsDoryAggregateLayout,
    sets: Vec<BlsDoryDeferredOpeningSet>,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: &Path,
) -> Result<(Vec<BlsDoryOpeningClaim>, Vec<u8>), BlsDoryAggregateError> {
    let claim_count = sets.iter().try_fold(0usize, |count, set| {
        count
            .checked_add(set.claims().len())
            .ok_or(BlsDoryAggregateError::InvalidClaimCount)
    })?;
    if claim_count != BLS_DORY_COMPOSED_AGGREGATE_CLAIMS {
        return Err(BlsDoryAggregateError::InvalidClaimCount);
    }
    prove_bls_dory_deferred_opening_sets_consuming_with_optional_scratch(
        public_binding,
        layout,
        sets,
        setup,
        Some(scratch_directory),
        BLS_DORY_COMPOSED_AGGREGATE_CLAIMS,
    )
}

fn prove_bls_dory_deferred_opening_sets_consuming_with_optional_scratch(
    public_binding: &[u8],
    layout: BlsDoryAggregateLayout,
    sets: Vec<BlsDoryDeferredOpeningSet>,
    setup: &DeterministicBlsDorySetup,
    scratch_directory: Option<&Path>,
    maximum_claims: usize,
) -> Result<(Vec<BlsDoryOpeningClaim>, Vec<u8>), BlsDoryAggregateError> {
    if sets.is_empty() {
        return Err(BlsDoryAggregateError::InvalidClaimCount);
    }
    let claim_count = sets.iter().try_fold(0usize, |count, set| {
        count
            .checked_add(set.polynomial_indices.len())
            .ok_or(BlsDoryAggregateError::InvalidClaimCount)
    })?;
    let polynomial_count = sets.iter().try_fold(0usize, |count, set| {
        count
            .checked_add(set.polynomials.len())
            .ok_or(BlsDoryAggregateError::InvalidClaimCount)
    })?;
    let mut polynomials = Vec::with_capacity(polynomial_count);
    let mut polynomial_indices = Vec::with_capacity(claim_count);
    let mut points = Vec::with_capacity(claim_count);
    let mut expected_claims = Vec::with_capacity(claim_count);
    for set in sets {
        let BlsDoryDeferredOpeningSet {
            polynomials: set_polynomials,
            polynomial_indices: set_indices,
            points: set_points,
            claims: set_claims,
        } = set;
        if set_indices.len() != set_points.len()
            || set_indices.len() != set_claims.len()
            || set_indices
                .iter()
                .any(|index| *index >= set_polynomials.len())
        {
            return Err(BlsDoryAggregateError::InvalidClaimCount);
        }
        let base = polynomials.len();
        for index in set_indices {
            polynomial_indices.push(
                base.checked_add(index)
                    .ok_or(BlsDoryAggregateError::InvalidClaimCount)?,
            );
        }
        polynomials.extend(set_polynomials);
        points.extend(set_points);
        expected_claims.extend(set_claims);
    }
    let polynomial_refs = polynomial_indices
        .iter()
        .map(|index| {
            polynomials
                .get(*index)
                .ok_or(BlsDoryAggregateError::InvalidClaimCount)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let prepared = prepare_bls_dory_opening_refs_with_claim_limit(
        public_binding,
        layout,
        &polynomial_refs,
        &points,
        setup,
        scratch_directory,
        maximum_claims,
    )?;
    if prepared.claims != expected_claims {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    drop(polynomial_refs);
    drop(polynomials);
    finish_prepared_bls_dory_opening(prepared, setup)
}

fn prove_bls_dory_deferred_opening_sets_with_optional_scratch(
    public_binding: &[u8],
    layout: BlsDoryAggregateLayout,
    sets: &[&BlsDoryDeferredOpeningSet],
    setup: &DeterministicBlsDorySetup,
    scratch_directory: Option<&Path>,
) -> Result<(Vec<BlsDoryOpeningClaim>, Vec<u8>), BlsDoryAggregateError> {
    if sets.is_empty() {
        return Err(BlsDoryAggregateError::InvalidClaimCount);
    }
    let claim_count = sets.iter().try_fold(0usize, |count, set| {
        count
            .checked_add(set.polynomial_indices.len())
            .ok_or(BlsDoryAggregateError::InvalidClaimCount)
    })?;
    let mut polynomials = Vec::with_capacity(claim_count);
    let mut points = Vec::with_capacity(claim_count);
    let mut expected_claims = Vec::with_capacity(claim_count);
    for set in sets {
        for (index, point) in set.polynomial_indices.iter().zip(&set.points) {
            polynomials.push(&set.polynomials[*index]);
            points.push(point.clone());
        }
        expected_claims.extend_from_slice(&set.claims);
    }
    let (claims, proof) = prove_bls_dory_opening_refs_with_scratch(
        public_binding,
        layout,
        &polynomials,
        &points,
        setup,
        scratch_directory,
    )?;
    if claims != expected_claims {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    Ok((claims, proof))
}

/// Verify the bounded aggregate after absorbing every public claim.
pub fn verify_bls_dory_openings(
    public_binding: &[u8],
    layout: BlsDoryAggregateLayout,
    claims: &[BlsDoryOpeningClaim],
    proof: &[u8],
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDoryAggregateError> {
    verify_bls_dory_openings_with_claim_limit(
        public_binding,
        layout,
        claims,
        proof,
        setup,
        MAX_BLS_DORY_AGGREGATE_CLAIMS,
    )
}

/// Verify exactly the shared-128 plus native-BLAKE3-6 composition without
/// widening the generic public claim cap.
#[cfg(any(test, feature = "whir-prototype"))]
pub(crate) fn verify_bls_dory_composed_openings(
    public_binding: &[u8],
    layout: BlsDoryAggregateLayout,
    claims: &[BlsDoryOpeningClaim],
    proof: &[u8],
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDoryAggregateError> {
    if claims.len() != BLS_DORY_COMPOSED_AGGREGATE_CLAIMS {
        return Err(BlsDoryAggregateError::InvalidClaimCount);
    }
    verify_bls_dory_openings_with_claim_limit(
        public_binding,
        layout,
        claims,
        proof,
        setup,
        BLS_DORY_COMPOSED_AGGREGATE_CLAIMS,
    )
}

fn verify_bls_dory_openings_with_claim_limit(
    public_binding: &[u8],
    layout: BlsDoryAggregateLayout,
    claims: &[BlsDoryOpeningClaim],
    proof: &[u8],
    setup: &DeterministicBlsDorySetup,
    maximum_claims: usize,
) -> Result<(), BlsDoryAggregateError> {
    validate_public_inputs_with_claim_limit(public_binding, claims.len(), maximum_claims)?;
    setup
        .validate()
        .map_err(|_| BlsDoryAggregateError::InvalidSetup)?;
    let parsed = decode_aggregate_proof(proof, claims.len(), layout)?;
    if setup.max_log_n() < layout.variables()
        || claims
            .iter()
            .any(|claim| claim.point.len() != layout.variables())
    {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }

    let mut transcript = statement_transcript(
        public_binding,
        &setup.identity(),
        claims,
        parsed.nu,
        parsed.sigma,
    )?;
    let batching = batching_challenges(&mut transcript, claims.len());
    let terminal = verify_distinct_point_sumcheck(
        claims,
        &batching,
        &parsed.sumcheck_rounds,
        &mut transcript,
    )?;
    let combined_commitment = claims
        .iter()
        .zip(batching.iter().zip(&terminal.equality_values))
        .fold(
            BlsDoryGt::identity(),
            |combined, (claim, (rho, equality))| {
                combined + claim.commitment.scale(&(*rho * equality))
            },
        );
    append_combined_opening(
        &mut transcript,
        &combined_commitment,
        &terminal.random_point,
        &terminal.final_claim,
    );

    verify::<_, BlsDoryCurve, BlsDoryG1Routines, BlsDoryG2Routines, _>(
        combined_commitment,
        terminal.final_claim,
        &terminal.random_point,
        &parsed.dory_proof,
        setup.verifier().clone(),
        &mut transcript,
    )
    .map_err(dory_error)
}

fn validate_layout(nu: usize, sigma: usize) -> Result<(), BlsDoryAggregateError> {
    let variables = nu
        .checked_add(sigma)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    if variables == 0 || variables > MAX_BLS_DORY_SETUP_VARIABLES || nu > sigma {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }
    Ok(())
}

fn validate_public_inputs_with_claim_limit(
    public_binding: &[u8],
    claims: usize,
    maximum_claims: usize,
) -> Result<(), BlsDoryAggregateError> {
    if public_binding.len() > MAX_PUBLIC_BINDING_BYTES {
        return Err(BlsDoryAggregateError::PublicBindingTooLarge);
    }
    if claims == 0 || claims > maximum_claims {
        return Err(BlsDoryAggregateError::InvalidClaimCount);
    }
    Ok(())
}

fn dory_error(error: impl std::fmt::Display) -> BlsDoryAggregateError {
    BlsDoryAggregateError::Dory(error.to_string())
}

fn statement_transcript(
    public_binding: &[u8],
    setup_identity: &[u8; 32],
    claims: &[BlsDoryOpeningClaim],
    nu: usize,
    sigma: usize,
) -> Result<BlsDoryTranscript, BlsDoryAggregateError> {
    validate_layout(nu, sigma)?;
    let variables = nu + sigma;
    if claims.iter().any(|claim| claim.point.len() != variables) {
        return Err(BlsDoryAggregateError::InvalidDimension);
    }
    let mut transcript = BlsDoryTranscript::new(b"distinct-opening-aggregate");
    transcript.append_bytes(b"suite-version", &BLS_DORY_AGGREGATE_VERSION.to_le_bytes());
    transcript.append_bytes(b"public-binding", public_binding);
    transcript.append_bytes(b"setup-identity", setup_identity);
    transcript.append_bytes(b"claim-count", &(claims.len() as u64).to_le_bytes());
    transcript.append_bytes(b"variables", &(variables as u64).to_le_bytes());
    transcript.append_bytes(b"nu", &(nu as u64).to_le_bytes());
    transcript.append_bytes(b"sigma", &(sigma as u64).to_le_bytes());
    for claim in claims {
        transcript.append_group(b"commitment", &claim.commitment);
        for coordinate in &claim.point {
            transcript.append_field(b"point-coordinate", coordinate);
        }
        transcript.append_field(b"claimed-evaluation", &claim.evaluation);
    }
    Ok(transcript)
}

fn batching_challenges(transcript: &mut BlsDoryTranscript, count: usize) -> Vec<BlsDoryFr> {
    (0..count)
        .map(|_| transcript.challenge_scalar(b"claim-batching-challenge"))
        .collect()
}

fn append_sumcheck_round(transcript: &mut BlsDoryTranscript, round: &[BlsDoryFr; 3]) {
    transcript.append_field(b"sumcheck-at-zero", &round[0]);
    transcript.append_field(b"sumcheck-at-one", &round[1]);
    transcript.append_field(b"sumcheck-at-two", &round[2]);
}

fn append_combined_opening(
    transcript: &mut BlsDoryTranscript,
    commitment: &BlsDoryGt,
    point: &[BlsDoryFr],
    evaluation: &BlsDoryFr,
) {
    transcript.append_group(b"combined-commitment", commitment);
    for coordinate in point {
        transcript.append_field(b"combined-point", coordinate);
    }
    transcript.append_field(b"combined-evaluation", evaluation);
}

struct SumcheckTerminal {
    random_point: Vec<BlsDoryFr>,
    final_claim: BlsDoryFr,
    equality_values: Vec<BlsDoryFr>,
}

struct SumcheckProverOutput {
    rounds: Vec<[BlsDoryFr; 3]>,
    terminal: SumcheckTerminal,
    #[cfg(test)]
    unique_polynomial_tables: usize,
    #[cfg(test)]
    peak_additional_coefficients: usize,
    #[cfg(test)]
    compressed_pair_count: usize,
    #[cfg(test)]
    compressed_pair_folds: usize,
}

struct FoldScratch<'a> {
    directory: &'a Path,
    context_digest: [u8; 32],
}

impl<'a> FoldScratch<'a> {
    fn new(directory: &'a Path, context_digest: [u8; 32]) -> Result<Self, BlsDoryAggregateError> {
        if !directory.is_absolute() || !directory.is_dir() || context_digest == [0; 32] {
            return Err(BlsDoryAggregateError::ProverStorage);
        }
        Ok(Self {
            directory,
            context_digest,
        })
    }
}

fn aggregate_compact_source_parent_digest(
    source_digest: [u8; 32],
    mapped_digest: [u8; 32],
    transition_parent: [u8; 32],
    mapped_parent: [u8; 32],
) -> Result<[u8; 32], BlsDoryAggregateError> {
    let mut hasher = blake3::Hasher::new_derive_key(
        "CommonFoundry/ForgeMatrix/BlsDoryAggregateCompactParent/v1",
    );
    for digest in [
        source_digest,
        mapped_digest,
        transition_parent,
        mapped_parent,
    ] {
        if digest == [0; 32] {
            return Err(BlsDoryAggregateError::ProverStorage);
        }
        hasher.update(&digest);
    }
    let digest = *hasher.finalize().as_bytes();
    if digest == [0; 32] {
        return Err(BlsDoryAggregateError::ProverStorage);
    }
    Ok(digest)
}

fn aggregate_word_fold_digest(
    source_digest: [u8; 32],
    initial_parent: [u8; 32],
    challenges: &[BlsDoryFr],
) -> Result<[u8; 32], BlsDoryAggregateError> {
    if source_digest == [0; 32]
        || initial_parent == [0; 32]
        || challenges.is_empty()
        || challenges.len() > AGGREGATE_SOURCE_FOLD_GENERATIONS
    {
        return Err(BlsDoryAggregateError::ProverStorage);
    }
    let mut hasher =
        blake3::Hasher::new_derive_key("CommonFoundry/ForgeMatrix/BlsDoryAggregateWordFold/v1");
    hasher.update(&source_digest);
    hasher.update(&initial_parent);
    hasher.update(&(challenges.len() as u32).to_le_bytes());
    let mut encoded = Vec::with_capacity(challenges.len().saturating_mul(32));
    for challenge in challenges {
        append_serialized(&mut encoded, challenge)?;
    }
    hasher.update(&encoded);
    let digest = *hasher.finalize().as_bytes();
    if digest == [0; 32] {
        return Err(BlsDoryAggregateError::ProverStorage);
    }
    Ok(digest)
}

fn aggregate_compact_source_fold_digest(
    context_digest: [u8; 32],
    source_digest: [u8; 32],
    mapped_digest: [u8; 32],
    source_parent: [u8; 32],
    role: AggregateCompactFoldRole,
    challenges: &[BlsDoryFr],
) -> Result<[u8; 32], BlsDoryAggregateError> {
    if [context_digest, source_digest, mapped_digest, source_parent].contains(&[0; 32])
        || challenges.is_empty()
        || challenges.len() > AGGREGATE_SOURCE_FOLD_GENERATIONS
    {
        return Err(BlsDoryAggregateError::ProverStorage);
    }
    let mut hasher = blake3::Hasher::new_derive_key(
        "CommonFoundry/ForgeMatrix/BlsDoryAggregateCompactSourceFold/v1",
    );
    for digest in [context_digest, source_digest, mapped_digest, source_parent] {
        hasher.update(&digest);
    }
    hasher.update(&[match role {
        AggregateCompactFoldRole::Transition => 0,
        AggregateCompactFoldRole::Mapped => 1,
    }]);
    hasher.update(&(challenges.len() as u32).to_le_bytes());
    let mut encoded = Vec::with_capacity(challenges.len().saturating_mul(32));
    for challenge in challenges {
        append_serialized(&mut encoded, challenge)?;
    }
    hasher.update(&encoded);
    let digest = *hasher.finalize().as_bytes();
    if digest == [0; 32] {
        return Err(BlsDoryAggregateError::ProverStorage);
    }
    Ok(digest)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AggregateCompactFoldRole {
    Transition,
    Mapped,
}

struct AggregateCompactFoldView {
    source: Arc<BlsDoryCompactArtifact>,
    source_parent: [u8; 32],
    context_digest: [u8; 32],
    role: AggregateCompactFoldRole,
    challenges: Vec<BlsDoryFr>,
    mapped_dictionary: Arc<Vec<BlsDoryFr>>,
    mapped_digest: [u8; 32],
    explicit_len: usize,
}

impl AggregateCompactFoldView {
    fn validate_lineage(&self, expected: [u8; 32]) -> Result<(), BlsDoryAggregateError> {
        if aggregate_compact_source_fold_digest(
            self.context_digest,
            self.source.digest(),
            self.mapped_digest,
            self.source_parent,
            self.role,
            &self.challenges,
        )? != expected
        {
            return Err(BlsDoryAggregateError::ProverStorage);
        }
        Ok(())
    }

    fn for_each_scalar(
        &self,
        mut visitor: impl FnMut(BlsDoryFr),
    ) -> Result<(), BlsDoryAggregateError> {
        let spec = self.source.spec();
        if self.challenges.is_empty()
            || self.challenges.len() > AGGREGATE_SOURCE_FOLD_GENERATIONS
            || self.source.dictionary().len() != 16
            || self
                .source
                .dictionary()
                .iter()
                .enumerate()
                .any(|(digit, scalar)| *scalar != BlsDoryFr::from_u64(digit as u64))
            || self.mapped_dictionary.len() != 16
            || spec.signed_word_selectors != 0
            || spec.word_scalar_count == 0
            || spec.word_scalar_count >= spec.explicit_scalar_count
        {
            return Err(BlsDoryAggregateError::ProverStorage);
        }
        let block_len = 1usize
            .checked_shl(
                u32::try_from(self.challenges.len())
                    .map_err(|_| BlsDoryAggregateError::ProverStorage)?,
            )
            .ok_or(BlsDoryAggregateError::ProverStorage)?;
        let expected = usize::try_from(spec.explicit_scalar_count)
            .map_err(|_| BlsDoryAggregateError::ProverStorage)?
            .div_ceil(block_len);
        if expected != self.explicit_len || block_len > 1 << AGGREGATE_SOURCE_FOLD_GENERATIONS {
            return Err(BlsDoryAggregateError::ProverStorage);
        }
        let mut block = [BlsDoryFr::zero(); 1 << AGGREGATE_SOURCE_FOLD_GENERATIONS];
        let mut block_used = 0usize;
        let mut visited = 0usize;
        let mut failed = false;
        let result = self.source.for_each_encoded_scalar(|index, encoded| {
            block[block_used] = match encoded {
                CompactEncodedScalar::Word {
                    value,
                    signed: false,
                } if index < spec.word_scalar_count => match self.role {
                    AggregateCompactFoldRole::Transition => BlsDoryFr::from_u64(value),
                    AggregateCompactFoldRole::Mapped => BlsDoryFr::zero(),
                },
                CompactEncodedScalar::Code(code) if index >= spec.word_scalar_count => {
                    let digit = usize::from(code);
                    match self.role {
                        AggregateCompactFoldRole::Transition => self
                            .source
                            .dictionary()
                            .get(digit)
                            .copied()
                            .ok_or(BlsDoryCompactArtifactError::InvalidArtifact)?,
                        AggregateCompactFoldRole::Mapped => self
                            .mapped_dictionary
                            .get(digit)
                            .copied()
                            .ok_or(BlsDoryCompactArtifactError::InvalidArtifact)?,
                    }
                }
                _ => {
                    failed = true;
                    return Err(BlsDoryCompactArtifactError::InvalidArtifact);
                }
            };
            block_used += 1;
            if block_used == block_len {
                visitor(fold_aggregate_word_block(
                    &mut block,
                    block_len,
                    &self.challenges,
                ));
                visited += 1;
                block.fill(BlsDoryFr::zero());
                block_used = 0;
            }
            Ok(())
        });
        if failed || result.is_err() {
            return Err(BlsDoryAggregateError::ProverStorage);
        }
        if block_used != 0 {
            visitor(fold_aggregate_word_block(
                &mut block,
                block_len,
                &self.challenges,
            ));
            visited += 1;
        }
        if visited != expected {
            return Err(BlsDoryAggregateError::ProverStorage);
        }
        Ok(())
    }

    fn for_each_pair(
        &self,
        mut visitor: impl FnMut(BlsDoryFr, BlsDoryFr),
    ) -> Result<(), BlsDoryAggregateError> {
        let mut pending = None;
        self.for_each_scalar(|scalar| {
            if let Some(lower) = pending.take() {
                visitor(lower, scalar);
            } else {
                pending = Some(scalar);
            }
        })?;
        if let Some(lower) = pending {
            visitor(lower, BlsDoryFr::zero());
        }
        Ok(())
    }
}

struct AggregateWordFoldView {
    source: Arc<BlsDoryCompactArtifact>,
    initial_parent: [u8; 32],
    challenges: Vec<BlsDoryFr>,
    explicit_len: usize,
}

impl AggregateWordFoldView {
    fn validate_lineage(&self, expected: [u8; 32]) -> Result<(), BlsDoryAggregateError> {
        if aggregate_word_fold_digest(self.source.digest(), self.initial_parent, &self.challenges)?
            != expected
        {
            return Err(BlsDoryAggregateError::ProverStorage);
        }
        Ok(())
    }

    fn for_each_scalar(
        &self,
        mut visitor: impl FnMut(BlsDoryFr),
    ) -> Result<(), BlsDoryAggregateError> {
        if self.challenges.is_empty() || self.challenges.len() > AGGREGATE_SOURCE_FOLD_GENERATIONS {
            return Err(BlsDoryAggregateError::ProverStorage);
        }
        let spec = self.source.spec();
        if !aggregate_word_source_supported(&self.source) {
            return Err(BlsDoryAggregateError::ProverStorage);
        }
        let word_group_len = usize::try_from(spec.word_group_len)
            .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
        let block_len = 1usize
            .checked_shl(
                u32::try_from(self.challenges.len())
                    .map_err(|_| BlsDoryAggregateError::ProverStorage)?,
            )
            .ok_or(BlsDoryAggregateError::ProverStorage)?;
        let expected = usize::try_from(spec.explicit_scalar_count)
            .map_err(|_| BlsDoryAggregateError::ProverStorage)?
            .div_ceil(block_len);
        if expected != self.explicit_len || block_len > 1 << AGGREGATE_SOURCE_FOLD_GENERATIONS {
            return Err(BlsDoryAggregateError::ProverStorage);
        }
        let mut block = [BlsDoryFr::zero(); 1 << AGGREGATE_SOURCE_FOLD_GENERATIONS];
        let mut block_used = 0usize;
        let mut visited = 0usize;
        let mut failed = false;
        let read_result = self.source.for_each_encoded_scalar(|index, encoded| {
            block[block_used] = match encoded {
                CompactEncodedScalar::Word { value, signed } => {
                    let Some(selector) = usize::try_from(index)
                        .ok()
                        .and_then(|index| index.checked_div(word_group_len))
                    else {
                        failed = true;
                        return Err(BlsDoryCompactArtifactError::InvalidArtifact);
                    };
                    if signed != compact_selector_is_signed(selector, spec.signed_word_selectors) {
                        failed = true;
                        return Err(BlsDoryCompactArtifactError::InvalidArtifact);
                    }
                    if signed {
                        BlsDoryFr::from_i64(i64::from_le_bytes(value.to_le_bytes()))
                    } else {
                        BlsDoryFr::from_u64(value)
                    }
                }
                CompactEncodedScalar::Code(code) => self
                    .source
                    .dictionary()
                    .get(usize::from(code))
                    .copied()
                    .ok_or(BlsDoryCompactArtifactError::InvalidArtifact)?,
            };
            block_used += 1;
            if block_used == block_len {
                visitor(fold_aggregate_word_block(
                    &mut block,
                    block_len,
                    &self.challenges,
                ));
                visited += 1;
                block.fill(BlsDoryFr::zero());
                block_used = 0;
            }
            Ok(())
        });
        if failed || read_result.is_err() {
            return Err(BlsDoryAggregateError::ProverStorage);
        }
        if block_used != 0 {
            visitor(fold_aggregate_word_block(
                &mut block,
                block_len,
                &self.challenges,
            ));
            visited += 1;
        }
        if visited != expected {
            return Err(BlsDoryAggregateError::ProverStorage);
        }
        Ok(())
    }

    fn for_each_pair(
        &self,
        mut visitor: impl FnMut(BlsDoryFr, BlsDoryFr),
    ) -> Result<(), BlsDoryAggregateError> {
        let mut pending = None;
        self.for_each_scalar(|scalar| {
            if let Some(lower) = pending.take() {
                visitor(lower, scalar);
            } else {
                pending = Some(scalar);
            }
        })?;
        if let Some(lower) = pending {
            visitor(lower, BlsDoryFr::zero());
        }
        Ok(())
    }
}

fn aggregate_word_source_supported(source: &BlsDoryCompactArtifact) -> bool {
    let spec = source.spec();
    (spec.word_scalar_count == spec.explicit_scalar_count
        && source.dictionary() == [BlsDoryFr::zero()])
        || (spec.word_scalar_count < spec.explicit_scalar_count
            && spec.word_scalar_count == spec.word_group_len
            && spec.signed_word_selectors == 1
            && is_bounded_signed_dictionary(source.dictionary()))
}

fn fold_aggregate_word_block(
    block: &mut [BlsDoryFr; 1 << AGGREGATE_SOURCE_FOLD_GENERATIONS],
    block_len: usize,
    challenges: &[BlsDoryFr],
) -> BlsDoryFr {
    let mut width = block_len;
    for challenge in challenges {
        for index in 0..width / 2 {
            block[index] =
                block[index * 2] + *challenge * (block[index * 2 + 1] - block[index * 2]);
        }
        width /= 2;
    }
    debug_assert_eq!(width, 1);
    block[0]
}

struct AggregateCompactPair {
    transition_table: usize,
    mapped_table: usize,
    source: Arc<BlsDoryCompactArtifact>,
    mapped_dictionary: Arc<Vec<BlsDoryFr>>,
    mapped_digest: [u8; 32],
}

fn find_aggregate_compact_pairs(
    polynomials: &[&BlsDoryCommittedPolynomial],
) -> Vec<AggregateCompactPair> {
    let mut pairs = Vec::new();
    let mut used = vec![false; polynomials.len()];
    for (transition_table, polynomial) in polynomials.iter().enumerate() {
        let BlsDoryCoefficientStorage::CompactArtifact(source) = &polynomial.coefficients else {
            continue;
        };
        let spec = source.spec();
        let supported_source = source.dictionary().len() == 16
            && spec.signed_word_selectors == 0
            && source
                .dictionary()
                .iter()
                .enumerate()
                .all(|(digit, scalar)| *scalar == BlsDoryFr::from_u64(digit as u64))
            && spec.word_group_len >= 2
            && spec.word_group_len.is_power_of_two()
            && spec.scalar_count.is_multiple_of(spec.word_group_len)
            && spec
                .explicit_scalar_count
                .is_multiple_of(spec.word_group_len)
            && spec.word_scalar_count.is_multiple_of(spec.word_group_len)
            && spec.explicit_scalar_count > spec.word_scalar_count;
        if !supported_source {
            continue;
        }
        let candidates = polynomials
            .iter()
            .enumerate()
            .filter_map(|(mapped_table, candidate)| {
                let BlsDoryCoefficientStorage::MappedCompactArtifact(mapped) =
                    &candidate.coefficients
                else {
                    return None;
                };
                (Arc::ptr_eq(source, mapped.source())
                    && mapped.zero_prefix_count() == spec.word_scalar_count
                    && mapped.mapped_dictionary().len() == source.dictionary().len())
                .then_some((mapped_table, mapped))
            })
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            continue;
        }
        let (mapped_table, mapped) = candidates[0];
        if transition_table == mapped_table || used[transition_table] || used[mapped_table] {
            continue;
        }
        used[transition_table] = true;
        used[mapped_table] = true;
        pairs.push(AggregateCompactPair {
            transition_table,
            mapped_table,
            source: Arc::clone(source),
            mapped_dictionary: Arc::new(mapped.mapped_dictionary().to_vec()),
            mapped_digest: mapped.digest(),
        });
    }
    pairs
}

fn find_aggregate_word_tables(polynomials: &[&BlsDoryCommittedPolynomial]) -> Vec<usize> {
    polynomials
        .iter()
        .enumerate()
        .filter_map(|(table_index, polynomial)| {
            let BlsDoryCoefficientStorage::CompactArtifact(source) = &polynomial.coefficients
            else {
                return None;
            };
            aggregate_word_source_supported(source).then_some(table_index)
        })
        .collect()
}

fn two_tables_mut<T>(values: &mut [T], left: usize, right: usize) -> Option<(&mut T, &mut T)> {
    if left == right || left >= values.len() || right >= values.len() {
        return None;
    }
    if left < right {
        let (before, after) = values.split_at_mut(right);
        Some((&mut before[left], &mut after[0]))
    } else {
        let (before, after) = values.split_at_mut(left);
        Some((&mut after[0], &mut before[right]))
    }
}

fn install_aggregate_compact_pair(
    tables: &mut [FoldedPolynomialTable<'_>],
    pair: &AggregateCompactPair,
    source_parent: [u8; 32],
    context_digest: [u8; 32],
    challenges: Vec<BlsDoryFr>,
) -> Result<(), BlsDoryAggregateError> {
    let (transition, mapped) = two_tables_mut(tables, pair.transition_table, pair.mapped_table)
        .ok_or(BlsDoryAggregateError::ProverStorage)?;
    let child_logical_len = transition
        .logical_len
        .checked_div(2)
        .filter(|len| *len > 0 && mapped.logical_len / 2 == *len)
        .ok_or(BlsDoryAggregateError::ProverStorage)?;
    let child_explicit_len = transition.explicit_pair_count()?;
    if mapped.explicit_pair_count()? != child_explicit_len {
        return Err(BlsDoryAggregateError::ProverStorage);
    }
    let block_len = 1usize
        .checked_shl(
            u32::try_from(challenges.len()).map_err(|_| BlsDoryAggregateError::ProverStorage)?,
        )
        .ok_or(BlsDoryAggregateError::ProverStorage)?;
    let source_values = usize::try_from(pair.source.spec().explicit_scalar_count)
        .map_err(|_| BlsDoryAggregateError::ProverStorage)?
        .div_ceil(block_len);
    if source_values != child_explicit_len {
        return Err(BlsDoryAggregateError::ProverStorage);
    }
    transition.lineage_digest = aggregate_compact_source_fold_digest(
        context_digest,
        pair.source.digest(),
        pair.mapped_digest,
        source_parent,
        AggregateCompactFoldRole::Transition,
        &challenges,
    )?;
    mapped.lineage_digest = aggregate_compact_source_fold_digest(
        context_digest,
        pair.source.digest(),
        pair.mapped_digest,
        source_parent,
        AggregateCompactFoldRole::Mapped,
        &challenges,
    )?;
    transition.storage = FoldedPolynomialStorage::Compact(AggregateCompactFoldView {
        source: Arc::clone(&pair.source),
        source_parent,
        context_digest,
        role: AggregateCompactFoldRole::Transition,
        challenges: challenges.clone(),
        mapped_dictionary: Arc::clone(&pair.mapped_dictionary),
        mapped_digest: pair.mapped_digest,
        explicit_len: child_explicit_len,
    });
    mapped.storage = FoldedPolynomialStorage::Compact(AggregateCompactFoldView {
        source: Arc::clone(&pair.source),
        source_parent,
        context_digest,
        role: AggregateCompactFoldRole::Mapped,
        challenges,
        mapped_dictionary: Arc::clone(&pair.mapped_dictionary),
        mapped_digest: pair.mapped_digest,
        explicit_len: child_explicit_len,
    });
    transition.logical_len = child_logical_len;
    mapped.logical_len = child_logical_len;
    Ok(())
}

fn fold_aggregate_compact_pair(
    tables: &mut [FoldedPolynomialTable<'_>],
    pair: &AggregateCompactPair,
    challenge: BlsDoryFr,
    generation: usize,
    scratch: &FoldScratch<'_>,
) -> Result<(), BlsDoryAggregateError> {
    if generation == 0 || generation > AGGREGATE_SOURCE_FOLD_GENERATIONS {
        return Err(BlsDoryAggregateError::ProverStorage);
    }
    let (source_parent, context_digest, mut challenges) = if generation == 1 {
        let transition_parent = tables
            .get(pair.transition_table)
            .ok_or(BlsDoryAggregateError::ProverStorage)?
            .lineage_digest;
        let mapped_parent = tables
            .get(pair.mapped_table)
            .ok_or(BlsDoryAggregateError::ProverStorage)?
            .lineage_digest;
        (
            aggregate_compact_source_parent_digest(
                pair.source.digest(),
                pair.mapped_digest,
                transition_parent,
                mapped_parent,
            )?,
            scratch.context_digest,
            Vec::new(),
        )
    } else {
        let transition = tables
            .get(pair.transition_table)
            .ok_or(BlsDoryAggregateError::ProverStorage)?;
        let mapped = tables
            .get(pair.mapped_table)
            .ok_or(BlsDoryAggregateError::ProverStorage)?;
        let transition_view = match (&transition.storage, &mapped.storage) {
            (
                FoldedPolynomialStorage::Compact(transition_view),
                FoldedPolynomialStorage::Compact(mapped_view),
            ) if transition_view.role == AggregateCompactFoldRole::Transition
                && mapped_view.role == AggregateCompactFoldRole::Mapped
                && Arc::ptr_eq(&transition_view.source, &mapped_view.source)
                && Arc::ptr_eq(&transition_view.source, &pair.source)
                && transition_view.challenges == mapped_view.challenges
                && transition_view.source_parent == mapped_view.source_parent
                && transition_view.context_digest == mapped_view.context_digest
                && transition_view.context_digest == scratch.context_digest
                && transition_view.mapped_digest == pair.mapped_digest
                && mapped_view.mapped_digest == pair.mapped_digest
                && transition_view
                    .validate_lineage(transition.lineage_digest)
                    .is_ok()
                && mapped_view.validate_lineage(mapped.lineage_digest).is_ok() =>
            {
                transition_view
            }
            _ => return Err(BlsDoryAggregateError::ProverStorage),
        };
        (
            transition_view.source_parent,
            transition_view.context_digest,
            transition_view.challenges.clone(),
        )
    };
    if challenges.len() != generation - 1 {
        return Err(BlsDoryAggregateError::ProverStorage);
    }
    challenges.push(challenge);
    install_aggregate_compact_pair(tables, pair, source_parent, context_digest, challenges)
}

fn fold_aggregate_word_table(
    table: &mut FoldedPolynomialTable<'_>,
    challenge: BlsDoryFr,
    generation: usize,
) -> Result<(), BlsDoryAggregateError> {
    if generation == 0 || generation > AGGREGATE_SOURCE_FOLD_GENERATIONS {
        return Err(BlsDoryAggregateError::ProverStorage);
    }
    let child_logical_len = table
        .logical_len
        .checked_div(2)
        .filter(|len| *len > 0)
        .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
    let child_explicit_len = table.explicit_pair_count()?;
    let (source, initial_parent, mut challenges) = if generation == 1 {
        let FoldedPolynomialStorage::Source(polynomial) = &table.storage else {
            return Err(BlsDoryAggregateError::ProverStorage);
        };
        let BlsDoryCoefficientStorage::CompactArtifact(source) = &polynomial.coefficients else {
            return Err(BlsDoryAggregateError::ProverStorage);
        };
        if !aggregate_word_source_supported(source) {
            return Err(BlsDoryAggregateError::ProverStorage);
        }
        (Arc::clone(source), table.lineage_digest, Vec::new())
    } else {
        let FoldedPolynomialStorage::WordCompact(view) = &table.storage else {
            return Err(BlsDoryAggregateError::ProverStorage);
        };
        view.validate_lineage(table.lineage_digest)?;
        if view.challenges.len() != generation - 1 {
            return Err(BlsDoryAggregateError::ProverStorage);
        }
        (
            Arc::clone(&view.source),
            view.initial_parent,
            view.challenges.clone(),
        )
    };
    challenges.push(challenge);
    table.lineage_digest =
        aggregate_word_fold_digest(source.digest(), initial_parent, &challenges)?;
    table.storage = FoldedPolynomialStorage::WordCompact(AggregateWordFoldView {
        source,
        initial_parent,
        challenges,
        explicit_len: child_explicit_len,
    });
    table.logical_len = child_logical_len;
    Ok(())
}

enum FoldedPolynomialStorage<'a> {
    Source(&'a BlsDoryCommittedPolynomial),
    Owned(Vec<BlsDoryFr>),
    Artifact(BlsDoryFoldArtifact),
    Compact(AggregateCompactFoldView),
    WordCompact(AggregateWordFoldView),
}

struct FoldedPolynomialTable<'a> {
    storage: FoldedPolynomialStorage<'a>,
    logical_len: usize,
    table_index: u32,
    lineage_digest: [u8; 32],
}

impl<'a> FoldedPolynomialTable<'a> {
    fn source(
        polynomial: &'a BlsDoryCommittedPolynomial,
        table_index: usize,
    ) -> Result<Self, BlsDoryAggregateError> {
        Ok(Self {
            storage: FoldedPolynomialStorage::Source(polynomial),
            logical_len: polynomial.coefficient_count(),
            table_index: u32::try_from(table_index)
                .map_err(|_| BlsDoryAggregateError::InvalidClaimCount)?,
            lineage_digest: committed_polynomial_fold_parent(polynomial)?,
        })
    }

    fn len(&self) -> usize {
        self.logical_len
    }

    fn explicit_len(&self) -> usize {
        match &self.storage {
            FoldedPolynomialStorage::Source(polynomial) => polynomial.explicit_coefficient_count(),
            FoldedPolynomialStorage::Owned(values) => values.len(),
            FoldedPolynomialStorage::Artifact(artifact) => {
                artifact.spec().explicit_scalar_count as usize
            }
            FoldedPolynomialStorage::Compact(view) => view.explicit_len,
            FoldedPolynomialStorage::WordCompact(view) => view.explicit_len,
        }
    }

    fn explicit_pair_count(&self) -> Result<usize, BlsDoryAggregateError> {
        if self.logical_len < 2
            || self.explicit_len() == 0
            || self.explicit_len() > self.logical_len
        {
            return Err(BlsDoryAggregateError::InvalidProofShape);
        }
        Ok(self.explicit_len().div_ceil(2))
    }

    fn for_each_pair(
        &self,
        mut visitor: impl FnMut(BlsDoryFr, BlsDoryFr),
    ) -> Result<(), BlsDoryAggregateError> {
        match &self.storage {
            FoldedPolynomialStorage::Source(polynomial) => {
                polynomial.for_each_coefficient_pair(&mut visitor)
            }
            FoldedPolynomialStorage::Owned(values) => {
                for_each_memory_pair(values, self.logical_len, &mut visitor)
            }
            FoldedPolynomialStorage::Artifact(artifact) => artifact
                .for_each_pair(|lower, upper| {
                    visitor(lower, upper);
                    Ok(())
                })
                .map_err(|_| BlsDoryAggregateError::ProverStorage),
            FoldedPolynomialStorage::Compact(view) => {
                view.validate_lineage(self.lineage_digest)?;
                view.for_each_pair(visitor)
            }
            FoldedPolynomialStorage::WordCompact(view) => {
                view.validate_lineage(self.lineage_digest)?;
                view.for_each_pair(visitor)
            }
        }
    }

    fn fold(
        &mut self,
        challenge: BlsDoryFr,
        generation: usize,
        scratch: Option<&FoldScratch<'_>>,
    ) -> Result<(), BlsDoryAggregateError> {
        let child_logical_len = self
            .logical_len
            .checked_div(2)
            .filter(|count| *count > 0)
            .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
        let child_explicit_len = self.explicit_pair_count()?;
        if let Some(scratch) = scratch {
            let spec = BlsDoryFoldArtifactSpec {
                context_digest: scratch.context_digest,
                table_index: self.table_index,
                generation: u32::try_from(generation)
                    .map_err(|_| BlsDoryAggregateError::InvalidDimension)?,
                scalar_count: u64::try_from(child_logical_len)
                    .map_err(|_| BlsDoryAggregateError::InvalidDimension)?,
                explicit_scalar_count: u64::try_from(child_explicit_len)
                    .map_err(|_| BlsDoryAggregateError::InvalidDimension)?,
                parent_digest: self.lineage_digest,
            };
            let mut writer = BlsDoryFoldArtifactWriter::create(scratch.directory, spec)
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
            match &self.storage {
                FoldedPolynomialStorage::Source(polynomial) => {
                    let mut write_failed = false;
                    polynomial.for_each_coefficient_pair(|lower, upper| {
                        if !write_failed
                            && writer
                                .write_scalar(&(lower + challenge * (upper - lower)))
                                .is_err()
                        {
                            write_failed = true;
                        }
                    })?;
                    if write_failed {
                        return Err(BlsDoryAggregateError::ProverStorage);
                    }
                }
                FoldedPolynomialStorage::Owned(values) => {
                    write_memory_fold(values, self.logical_len, challenge, &mut writer)?
                }
                FoldedPolynomialStorage::Artifact(artifact) => artifact
                    .for_each_pair(|lower, upper| {
                        writer.write_scalar(&(lower + challenge * (upper - lower)))
                    })
                    .map_err(|_| BlsDoryAggregateError::ProverStorage)?,
                FoldedPolynomialStorage::Compact(view) => {
                    view.validate_lineage(self.lineage_digest)?;
                    let mut write_failed = false;
                    view.for_each_pair(|lower, upper| {
                        if writer
                            .write_scalar(&(lower + challenge * (upper - lower)))
                            .is_err()
                        {
                            write_failed = true;
                        }
                    })?;
                    if write_failed {
                        return Err(BlsDoryAggregateError::ProverStorage);
                    }
                }
                FoldedPolynomialStorage::WordCompact(view) => {
                    view.validate_lineage(self.lineage_digest)?;
                    let mut write_failed = false;
                    view.for_each_pair(|lower, upper| {
                        if writer
                            .write_scalar(&(lower + challenge * (upper - lower)))
                            .is_err()
                        {
                            write_failed = true;
                        }
                    })?;
                    if write_failed {
                        return Err(BlsDoryAggregateError::ProverStorage);
                    }
                }
            }
            let artifact = writer
                .finish()
                .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
            self.lineage_digest = artifact.digest();
            self.storage = FoldedPolynomialStorage::Artifact(artifact);
            self.logical_len = child_logical_len;
            return Ok(());
        }

        match &mut self.storage {
            FoldedPolynomialStorage::Source(polynomial) => {
                let mut folded = Vec::with_capacity(child_explicit_len);
                polynomial.for_each_coefficient_pair(|lower, upper| {
                    folded.push(lower + challenge * (upper - lower));
                })?;
                self.storage = FoldedPolynomialStorage::Owned(folded);
            }
            FoldedPolynomialStorage::Owned(values) => {
                let mut folded = Vec::with_capacity(child_explicit_len);
                for_each_memory_pair(values, self.logical_len, &mut |lower, upper| {
                    folded.push(lower + challenge * (upper - lower));
                })?;
                *values = folded;
            }
            FoldedPolynomialStorage::Artifact(_) => {
                return Err(BlsDoryAggregateError::ProverStorage);
            }
            FoldedPolynomialStorage::Compact(_) => {
                return Err(BlsDoryAggregateError::ProverStorage);
            }
            FoldedPolynomialStorage::WordCompact(_) => {
                return Err(BlsDoryAggregateError::ProverStorage);
            }
        }
        self.logical_len = child_logical_len;
        Ok(())
    }

    fn single(&self) -> Result<BlsDoryFr, BlsDoryAggregateError> {
        if self.len() != 1 {
            return Err(BlsDoryAggregateError::InvalidProofShape);
        }
        match &self.storage {
            FoldedPolynomialStorage::Source(_) => Err(BlsDoryAggregateError::InvalidProofShape),
            FoldedPolynomialStorage::Owned(values) => Ok(values[0]),
            FoldedPolynomialStorage::Artifact(artifact) => {
                let mut value = None;
                artifact
                    .for_each_scalar(|scalar| {
                        value = Some(scalar);
                        Ok::<(), BlsDoryFoldArtifactError>(())
                    })
                    .map_err(|_| BlsDoryAggregateError::ProverStorage)?;
                value.ok_or(BlsDoryAggregateError::InvalidProofShape)
            }
            FoldedPolynomialStorage::Compact(view) => {
                view.validate_lineage(self.lineage_digest)?;
                let mut value = None;
                view.for_each_scalar(|scalar| value = Some(scalar))?;
                value.ok_or(BlsDoryAggregateError::InvalidProofShape)
            }
            FoldedPolynomialStorage::WordCompact(view) => {
                view.validate_lineage(self.lineage_digest)?;
                let mut value = None;
                view.for_each_scalar(|scalar| value = Some(scalar))?;
                value.ok_or(BlsDoryAggregateError::InvalidProofShape)
            }
        }
    }
}

fn for_each_memory_pair(
    values: &[BlsDoryFr],
    logical_len: usize,
    visitor: &mut impl FnMut(BlsDoryFr, BlsDoryFr),
) -> Result<(), BlsDoryAggregateError> {
    if logical_len < 2
        || !logical_len.is_power_of_two()
        || values.is_empty()
        || values.len() > logical_len
    {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    for pair in values.chunks_exact(2) {
        visitor(pair[0], pair[1]);
    }
    if !values.len().is_multiple_of(2) {
        visitor(values[values.len() - 1], BlsDoryFr::zero());
    }
    Ok(())
}

fn write_memory_fold(
    values: &[BlsDoryFr],
    logical_len: usize,
    challenge: BlsDoryFr,
    writer: &mut BlsDoryFoldArtifactWriter,
) -> Result<(), BlsDoryAggregateError> {
    let mut failed = false;
    for_each_memory_pair(values, logical_len, &mut |lower, upper| {
        if !failed
            && writer
                .write_scalar(&(lower + challenge * (upper - lower)))
                .is_err()
        {
            failed = true;
        }
    })?;
    if failed {
        return Err(BlsDoryAggregateError::ProverStorage);
    }
    Ok(())
}

fn committed_polynomial_fold_parent(
    polynomial: &BlsDoryCommittedPolynomial,
) -> Result<[u8; 32], BlsDoryAggregateError> {
    let mut commitment = Vec::new();
    polynomial
        .commitment
        .serialize_compressed(&mut commitment)
        .map_err(|_| BlsDoryAggregateError::InvalidEncoding)?;
    let mut hasher =
        blake3::Hasher::new_derive_key("CommonFoundry/ForgeMatrix/BlsDoryFoldParent/v1");
    hasher.update(&polynomial.setup_identity);
    hasher.update(&(polynomial.nu as u64).to_le_bytes());
    hasher.update(&(polynomial.sigma as u64).to_le_bytes());
    hasher.update(&commitment);
    Ok(*hasher.finalize().as_bytes())
}

fn prove_distinct_point_sumcheck(
    polynomials: &[&BlsDoryCommittedPolynomial],
    claims: &[BlsDoryOpeningClaim],
    batching: &[BlsDoryFr],
    transcript: &mut BlsDoryTranscript,
    scratch: Option<&FoldScratch<'_>>,
) -> Result<SumcheckProverOutput, BlsDoryAggregateError> {
    let variables = claims[0].point.len();
    let coefficient_count = 1usize
        .checked_shl(u32::try_from(variables).map_err(|_| BlsDoryAggregateError::InvalidDimension)?)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    if polynomials.len() != claims.len()
        || claims.len() != batching.len()
        || polynomials
            .iter()
            .any(|polynomial| polynomial.coefficient_count() != coefficient_count)
    {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }

    let mut unique_polynomials = Vec::<&BlsDoryCommittedPolynomial>::new();
    let mut claim_table_indices = Vec::with_capacity(polynomials.len());
    for polynomial in polynomials {
        let table_index = unique_polynomials
            .iter()
            .position(|existing| existing.shares_coefficient_source(polynomial))
            .unwrap_or_else(|| {
                unique_polynomials.push(*polynomial);
                unique_polynomials.len() - 1
            });
        claim_table_indices.push(table_index);
    }
    let mut polynomial_tables = unique_polynomials
        .iter()
        .enumerate()
        .map(|(table_index, polynomial)| FoldedPolynomialTable::source(polynomial, table_index))
        .collect::<Result<Vec<_>, _>>()?;
    let compact_pairs = if scratch.is_some() {
        find_aggregate_compact_pairs(&unique_polynomials)
    } else {
        Vec::new()
    };
    let word_tables = if scratch.is_some() {
        find_aggregate_word_tables(&unique_polynomials)
    } else {
        Vec::new()
    };
    let mut table_claim_indices = vec![Vec::new(); unique_polynomials.len()];
    for (claim_index, table_index) in claim_table_indices.iter().copied().enumerate() {
        table_claim_indices[table_index].push(claim_index);
    }
    let mut equality_prefixes = vec![BlsDoryFr::one(); claims.len()];
    let mut current_claim = claims
        .iter()
        .zip(batching)
        .fold(BlsDoryFr::zero(), |sum, (claim, rho)| {
            sum + *rho * claim.evaluation
        });
    let mut rounds = Vec::with_capacity(variables);
    let mut random_point = Vec::with_capacity(variables);
    #[cfg(test)]
    let mut compressed_pair_folds = 0usize;

    for round_index in 0..variables {
        let mut message = [BlsDoryFr::zero(); 3];
        for (table, claim_indices) in polynomial_tables.iter().zip(&table_claim_indices) {
            accumulate_distinct_point_round(
                table,
                claim_indices,
                claims,
                batching,
                round_index,
                &equality_prefixes,
                &mut message,
            )?;
        }
        if message[0] + message[1] != current_claim {
            return Err(BlsDoryAggregateError::SumcheckFailed);
        }
        append_sumcheck_round(transcript, &message);
        let challenge = transcript.challenge_scalar(b"sumcheck-round-challenge");
        current_claim = interpolate_quadratic(message, challenge)?;
        random_point.push(challenge);
        let generation = round_index + 1;
        if let Some(scratch) = scratch.filter(|_| {
            generation <= AGGREGATE_SOURCE_FOLD_GENERATIONS
                && (!compact_pairs.is_empty() || !word_tables.is_empty())
        }) {
            let mut compressed_tables = vec![false; polynomial_tables.len()];
            for pair in &compact_pairs {
                let can_compress = generation == 1
                    || polynomial_tables
                        .get(pair.transition_table)
                        .and_then(|table| match &table.storage {
                            FoldedPolynomialStorage::Compact(view) => {
                                Some(view.challenges.len() < AGGREGATE_SOURCE_FOLD_GENERATIONS)
                            }
                            _ => None,
                        })
                        .unwrap_or(false);
                if can_compress {
                    fold_aggregate_compact_pair(
                        &mut polynomial_tables,
                        pair,
                        challenge,
                        generation,
                        scratch,
                    )?;
                    #[cfg(test)]
                    {
                        compressed_pair_folds += 1;
                    }
                    compressed_tables[pair.transition_table] = true;
                    compressed_tables[pair.mapped_table] = true;
                }
            }
            for table_index in &word_tables {
                let table = polynomial_tables
                    .get_mut(*table_index)
                    .ok_or(BlsDoryAggregateError::ProverStorage)?;
                fold_aggregate_word_table(table, challenge, generation)?;
                compressed_tables[*table_index] = true;
            }
            for (table_index, table) in polynomial_tables.iter_mut().enumerate() {
                if !compressed_tables[table_index] {
                    table.fold(challenge, generation, Some(scratch))?;
                }
            }
        } else {
            for table in &mut polynomial_tables {
                table.fold(challenge, generation, scratch)?;
            }
        }
        for (prefix, claim) in equality_prefixes.iter_mut().zip(claims) {
            let coordinate = claim.point[round_index];
            *prefix = *prefix
                * ((BlsDoryFr::one() - coordinate) * (BlsDoryFr::one() - challenge)
                    + coordinate * challenge);
        }
        rounds.push(message);
    }

    let terminal = claim_table_indices
        .iter()
        .zip(equality_prefixes.iter().zip(batching))
        .try_fold(BlsDoryFr::zero(), |sum, (table_index, (equality, rho))| {
            Ok(sum + polynomial_tables[*table_index].single()? * equality * rho)
        })?;
    if terminal != current_claim {
        return Err(BlsDoryAggregateError::SumcheckFailed);
    }
    Ok(SumcheckProverOutput {
        rounds,
        terminal: SumcheckTerminal {
            random_point,
            final_claim: current_claim,
            equality_values: equality_prefixes,
        },
        #[cfg(test)]
        unique_polynomial_tables: unique_polynomials.len(),
        #[cfg(test)]
        peak_additional_coefficients: if scratch.is_some() {
            0
        } else {
            unique_polynomials.len() * (coefficient_count / 2)
        },
        #[cfg(test)]
        compressed_pair_count: compact_pairs.len(),
        #[cfg(test)]
        compressed_pair_folds,
    })
}

fn accumulate_distinct_point_round(
    polynomial: &FoldedPolynomialTable<'_>,
    claim_indices: &[usize],
    claims: &[BlsDoryOpeningClaim],
    batching: &[BlsDoryFr],
    round_index: usize,
    equality_prefixes: &[BlsDoryFr],
    message: &mut [BlsDoryFr; 3],
) -> Result<(), BlsDoryAggregateError> {
    let first_claim = claim_indices
        .first()
        .and_then(|index| claims.get(*index))
        .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
    if claims.len() != batching.len()
        || claims.len() != equality_prefixes.len()
        || claim_indices.iter().any(|index| *index >= claims.len())
    {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let remaining_variables = first_claim
        .point
        .len()
        .checked_sub(round_index)
        .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
    let expected_len = 1usize
        .checked_shl(
            u32::try_from(remaining_variables)
                .map_err(|_| BlsDoryAggregateError::InvalidDimension)?,
        )
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    if polynomial.len() != expected_len || polynomial.len() < 2 {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let explicit_pairs = polynomial.explicit_pair_count()?;
    if explicit_pairs > expected_len / 2 {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }

    let mut weights = claim_indices
        .iter()
        .map(|index| EqualityWeightIterator::new(&claims[*index].point[round_index + 1..]))
        .collect::<Vec<_>>();
    let mut visited = 0usize;
    let mut missing_weight = false;
    polynomial.for_each_pair(|lower, upper| {
        let value_two = upper + upper - lower;
        for (claim_index, weights) in claim_indices.iter().zip(&mut weights) {
            let claim = &claims[*claim_index];
            let Some(suffix_weight) = weights.next() else {
                missing_weight = true;
                continue;
            };
            let coordinate = claim.point[round_index];
            let equality_scale = equality_prefixes[*claim_index] * suffix_weight;
            let equality_zero = equality_scale * (BlsDoryFr::one() - coordinate);
            let equality_one = equality_scale * coordinate;
            let equality_two = equality_one + equality_one - equality_zero;
            let rho = batching[*claim_index];
            message[0] = message[0] + rho * lower * equality_zero;
            message[1] = message[1] + rho * upper * equality_one;
            message[2] = message[2] + rho * value_two * equality_two;
        }
        visited += 1;
    })?;
    if missing_weight || visited != explicit_pairs {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    Ok(())
}

struct EqualityWeightIterator<'a> {
    point: &'a [BlsDoryFr],
    stack: Vec<(usize, BlsDoryFr)>,
}

impl<'a> EqualityWeightIterator<'a> {
    fn new(point: &'a [BlsDoryFr]) -> Self {
        Self {
            point,
            stack: vec![(point.len(), BlsDoryFr::one())],
        }
    }
}

impl Iterator for EqualityWeightIterator<'_> {
    type Item = BlsDoryFr;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((remaining, prefix)) = self.stack.pop() {
            if remaining == 0 {
                return Some(prefix);
            }
            let coordinate = self.point[remaining - 1];
            self.stack.push((remaining - 1, prefix * coordinate));
            self.stack
                .push((remaining - 1, prefix * (BlsDoryFr::one() - coordinate)));
        }
        None
    }
}

fn verify_distinct_point_sumcheck(
    claims: &[BlsDoryOpeningClaim],
    batching: &[BlsDoryFr],
    rounds: &[[BlsDoryFr; 3]],
    transcript: &mut BlsDoryTranscript,
) -> Result<SumcheckTerminal, BlsDoryAggregateError> {
    let variables = claims[0].point.len();
    if rounds.len() != variables {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let mut current_claim = claims
        .iter()
        .zip(batching)
        .fold(BlsDoryFr::zero(), |sum, (claim, rho)| {
            sum + *rho * claim.evaluation
        });
    let mut random_point = Vec::with_capacity(variables);
    for message in rounds {
        if message[0] + message[1] != current_claim {
            return Err(BlsDoryAggregateError::SumcheckFailed);
        }
        append_sumcheck_round(transcript, message);
        let challenge = transcript.challenge_scalar(b"sumcheck-round-challenge");
        current_claim = interpolate_quadratic(*message, challenge)?;
        random_point.push(challenge);
    }
    let equality_values = claims
        .iter()
        .map(|claim| equality_evaluation(&claim.point, &random_point))
        .collect();
    Ok(SumcheckTerminal {
        random_point,
        final_claim: current_claim,
        equality_values,
    })
}

fn equality_evaluation(point: &[BlsDoryFr], evaluation_point: &[BlsDoryFr]) -> BlsDoryFr {
    point
        .iter()
        .zip(evaluation_point)
        .fold(BlsDoryFr::one(), |product, (left, right)| {
            product * ((BlsDoryFr::one() - *left) * (BlsDoryFr::one() - *right) + *left * right)
        })
}

fn interpolate_quadratic(
    evaluations: [BlsDoryFr; 3],
    point: BlsDoryFr,
) -> Result<BlsDoryFr, BlsDoryAggregateError> {
    let two_inverse = BlsDoryFr::from_u64(2)
        .inv()
        .ok_or(BlsDoryAggregateError::SumcheckFailed)?;
    let second_difference = evaluations[2] - evaluations[1] - evaluations[1] + evaluations[0];
    Ok(evaluations[0]
        + point * (evaluations[1] - evaluations[0])
        + point * (point - BlsDoryFr::one()) * two_inverse * second_difference)
}

fn combine_polynomials_for_opening(
    polynomials: &[&BlsDoryCommittedPolynomial],
    lambdas: &[BlsDoryFr],
    point: &[BlsDoryFr],
    nu: usize,
    sigma: usize,
) -> Result<(Vec<BlsDoryG1>, BlsDoryGt, Vec<BlsDoryFr>), BlsDoryAggregateError> {
    let nu = u32::try_from(nu).map_err(|_| BlsDoryAggregateError::InvalidDimension)?;
    let sigma = u32::try_from(sigma).map_err(|_| BlsDoryAggregateError::InvalidDimension)?;
    let row_count = 1usize
        .checked_shl(nu)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let column_count = 1usize
        .checked_shl(sigma)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    let coefficient_count = row_count
        .checked_mul(column_count)
        .ok_or(BlsDoryAggregateError::InvalidDimension)?;
    if polynomials.is_empty()
        || polynomials.len() != lambdas.len()
        || point.len() != (nu + sigma) as usize
        || polynomials
            .iter()
            .any(|polynomial| polynomial.coefficient_count() != coefficient_count)
    {
        return Err(BlsDoryAggregateError::MixedStatement);
    }

    let mut grouped = Vec::<(&BlsDoryCommittedPolynomial, BlsDoryFr)>::new();
    for (polynomial, lambda) in polynomials.iter().zip(lambdas) {
        if let Some((_, scale)) = grouped
            .iter_mut()
            .find(|(existing, _)| existing.shares_coefficient_source(polynomial))
        {
            *scale = *scale + *lambda;
        } else {
            grouped.push((*polynomial, *lambda));
        }
    }

    let mut rows = vec![BlsDoryG1::identity(); row_count];
    let mut commitment = BlsDoryGt::identity();
    for (polynomial, lambda) in &grouped {
        if polynomial.row_commitments.len() != rows.len() {
            return Err(BlsDoryAggregateError::MixedStatement);
        }
        for (combined, row) in rows.iter_mut().zip(&polynomial.row_commitments) {
            *combined = *combined + row.scale(lambda);
        }
        commitment = commitment + polynomial.commitment.scale(lambda);
    }

    let (left, _) = compute_left_right_vectors(point, nu as usize, sigma as usize);
    let mut product = vec![BlsDoryFr::zero(); column_count];
    for (polynomial, lambda) in grouped {
        polynomial.accumulate_vector_matrix_product(&left, lambda, &mut product)?;
    }
    Ok((rows, commitment, product))
}

type BlsDoryProof = DoryProof<BlsDoryG1, BlsDoryG2, BlsDoryGt>;

struct ParsedAggregateProof {
    nu: usize,
    sigma: usize,
    sumcheck_rounds: Vec<[BlsDoryFr; 3]>,
    dory_proof: BlsDoryProof,
}

fn encode_aggregate_proof(
    claims: usize,
    variables: usize,
    nu: usize,
    sigma: usize,
    sumcheck_rounds: &[[BlsDoryFr; 3]],
    dory_proof: &BlsDoryProof,
) -> Result<Vec<u8>, BlsDoryAggregateError> {
    if sumcheck_rounds.len() != variables || !valid_dory_shape(dory_proof, nu, sigma) {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let claims = u16::try_from(claims).map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    let variables =
        u16::try_from(variables).map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    let nu = u16::try_from(nu).map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    let sigma = u16::try_from(sigma).map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    let mut encoded = Vec::with_capacity(aggregate_wire_bytes(variables as usize, sigma as usize));
    encoded.extend_from_slice(&WIRE_MAGIC);
    encoded.extend_from_slice(&BLS_DORY_AGGREGATE_VERSION.to_le_bytes());
    encoded.extend_from_slice(&claims.to_le_bytes());
    encoded.extend_from_slice(&variables.to_le_bytes());
    encoded.extend_from_slice(&nu.to_le_bytes());
    encoded.extend_from_slice(&sigma.to_le_bytes());
    for round in sumcheck_rounds {
        for evaluation in round {
            append_serialized(&mut encoded, evaluation)?;
        }
    }
    encode_dory_proof(&mut encoded, dory_proof)?;
    if encoded.len() != aggregate_wire_bytes(variables as usize, sigma as usize)
        || encoded.len() > MAX_BLS_DORY_AGGREGATE_BYTES
    {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    Ok(encoded)
}

fn decode_aggregate_proof(
    encoded: &[u8],
    expected_claims: usize,
    expected_layout: BlsDoryAggregateLayout,
) -> Result<ParsedAggregateProof, BlsDoryAggregateError> {
    if encoded.len() < WIRE_HEADER_BYTES || encoded.len() > MAX_BLS_DORY_AGGREGATE_BYTES {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    if encoded[..8] != WIRE_MAGIC {
        return Err(BlsDoryAggregateError::InvalidEncoding);
    }
    let version = read_u16(encoded, 8)?;
    let claims = read_u16(encoded, 10)? as usize;
    let variables = read_u16(encoded, 12)? as usize;
    let nu = read_u16(encoded, 14)? as usize;
    let sigma = read_u16(encoded, 16)? as usize;
    if version != BLS_DORY_AGGREGATE_VERSION || claims != expected_claims {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    validate_layout(nu, sigma)?;
    if variables != nu + sigma || encoded.len() != aggregate_wire_bytes(variables, sigma) {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    if variables != expected_layout.variables()
        || nu != expected_layout.nu
        || sigma != expected_layout.sigma
    {
        return Err(BlsDoryAggregateError::MixedStatement);
    }

    let mut reader = Cursor::new(&encoded[WIRE_HEADER_BYTES..]);
    let mut sumcheck_rounds = Vec::with_capacity(variables);
    for _ in 0..variables {
        let mut round = [BlsDoryFr::zero(); 3];
        for evaluation in &mut round {
            *evaluation = read_serialized(&mut reader)?;
        }
        sumcheck_rounds.push(round);
    }
    let dory_start = WIRE_HEADER_BYTES + reader.position() as usize;
    let dory_bytes = &encoded[dory_start..];
    preflight_dory_encoding(dory_bytes, nu, sigma)?;
    let dory_proof = decode_dory_proof(dory_bytes, nu, sigma)?;

    let canonical =
        encode_aggregate_proof(claims, variables, nu, sigma, &sumcheck_rounds, &dory_proof)?;
    if canonical != encoded {
        return Err(BlsDoryAggregateError::InvalidEncoding);
    }
    Ok(ParsedAggregateProof {
        nu,
        sigma,
        sumcheck_rounds,
        dory_proof,
    })
}

fn valid_dory_shape(proof: &BlsDoryProof, nu: usize, sigma: usize) -> bool {
    proof.nu == nu
        && proof.sigma == sigma
        && proof.first_messages.len() == sigma
        && proof.second_messages.len() == sigma
        && proof.final_message.is_some()
}

fn encode_dory_proof(
    output: &mut Vec<u8>,
    proof: &BlsDoryProof,
) -> Result<(), BlsDoryAggregateError> {
    append_serialized(output, &proof.vmv_message.c)?;
    append_serialized(output, &proof.vmv_message.d2)?;
    append_serialized(output, &proof.vmv_message.e1)?;
    output.extend_from_slice(&(proof.first_messages.len() as u32).to_le_bytes());
    for message in &proof.first_messages {
        append_serialized(output, &message.d1_left)?;
        append_serialized(output, &message.d1_right)?;
        append_serialized(output, &message.d2_left)?;
        append_serialized(output, &message.d2_right)?;
        append_serialized(output, &message.e1_beta)?;
        append_serialized(output, &message.e2_beta)?;
    }
    for message in &proof.second_messages {
        append_serialized(output, &message.c_plus)?;
        append_serialized(output, &message.c_minus)?;
        append_serialized(output, &message.e1_plus)?;
        append_serialized(output, &message.e1_minus)?;
        append_serialized(output, &message.e2_plus)?;
        append_serialized(output, &message.e2_minus)?;
    }
    output.push(1);
    let final_message = proof
        .final_message
        .as_ref()
        .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
    append_serialized(output, &final_message.e1)?;
    append_serialized(output, &final_message.e2)?;
    output.extend_from_slice(&(proof.nu as u32).to_le_bytes());
    output.extend_from_slice(&(proof.sigma as u32).to_le_bytes());
    Ok(())
}

fn decode_dory_proof(
    encoded: &[u8],
    nu: usize,
    sigma: usize,
) -> Result<BlsDoryProof, BlsDoryAggregateError> {
    let mut reader = Cursor::new(encoded);
    let vmv_message = VMVMessage {
        c: read_serialized(&mut reader)?,
        d2: read_serialized(&mut reader)?,
        e1: read_serialized(&mut reader)?,
    };
    if read_cursor_u32(&mut reader)? as usize != sigma {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let mut first_messages = Vec::with_capacity(sigma);
    for _ in 0..sigma {
        first_messages.push(FirstReduceMessage {
            d1_left: read_serialized(&mut reader)?,
            d1_right: read_serialized(&mut reader)?,
            d2_left: read_serialized(&mut reader)?,
            d2_right: read_serialized(&mut reader)?,
            e1_beta: read_serialized(&mut reader)?,
            e2_beta: read_serialized(&mut reader)?,
        });
    }
    let mut second_messages = Vec::with_capacity(sigma);
    for _ in 0..sigma {
        second_messages.push(SecondReduceMessage {
            c_plus: read_serialized(&mut reader)?,
            c_minus: read_serialized(&mut reader)?,
            e1_plus: read_serialized(&mut reader)?,
            e1_minus: read_serialized(&mut reader)?,
            e2_plus: read_serialized(&mut reader)?,
            e2_minus: read_serialized(&mut reader)?,
        });
    }
    if read_cursor_u8(&mut reader)? != 1 {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let final_message = Some(ScalarProductMessage {
        e1: read_serialized(&mut reader)?,
        e2: read_serialized(&mut reader)?,
    });
    let decoded_nu = read_cursor_u32(&mut reader)? as usize;
    let decoded_sigma = read_cursor_u32(&mut reader)? as usize;
    if decoded_nu != nu || decoded_sigma != sigma || reader.position() as usize != encoded.len() {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    Ok(DoryProof {
        vmv_message,
        first_messages,
        second_messages,
        final_message,
        nu,
        sigma,
    })
}

fn preflight_dory_encoding(
    encoded: &[u8],
    nu: usize,
    sigma: usize,
) -> Result<(), BlsDoryAggregateError> {
    if encoded.len() != dory_wire_bytes(sigma) {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let vmv = 2 * gt_bytes() + g1_bytes();
    if read_u32(encoded, vmv)? as usize != sigma {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let first_round = 4 * gt_bytes() + g1_bytes() + g2_bytes();
    let second_round = 2 * gt_bytes() + 2 * g1_bytes() + 2 * g2_bytes();
    let final_flag = vmv + size_of::<u32>() + sigma * (first_round + second_round);
    if encoded.get(final_flag).copied() != Some(1) {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    let shape = final_flag + 1 + g1_bytes() + g2_bytes();
    if read_u32(encoded, shape)? as usize != nu
        || read_u32(encoded, shape + size_of::<u32>())? as usize != sigma
    {
        return Err(BlsDoryAggregateError::InvalidProofShape);
    }
    Ok(())
}

fn aggregate_wire_bytes(variables: usize, rounds: usize) -> usize {
    WIRE_HEADER_BYTES + variables * 3 * scalar_bytes() + dory_wire_bytes(rounds)
}

fn dory_wire_bytes(rounds: usize) -> usize {
    2 * gt_bytes()
        + g1_bytes()
        + size_of::<u32>()
        + rounds * (6 * gt_bytes() + 3 * g1_bytes() + 3 * g2_bytes())
        + 1
        + g1_bytes()
        + g2_bytes()
        + 2 * size_of::<u32>()
}

fn scalar_bytes() -> usize {
    BlsDoryFr::zero().compressed_size()
}

fn g1_bytes() -> usize {
    BlsDoryG1::identity().compressed_size()
}

fn g2_bytes() -> usize {
    BlsDoryG2::identity().compressed_size()
}

fn gt_bytes() -> usize {
    BlsDoryGt::identity().compressed_size()
}

fn append_serialized<T: DorySerialize>(
    output: &mut Vec<u8>,
    value: &T,
) -> Result<(), BlsDoryAggregateError> {
    value
        .serialize_compressed(output)
        .map_err(|_| BlsDoryAggregateError::InvalidEncoding)
}

fn read_serialized<T: DoryDeserialize>(
    reader: &mut Cursor<&[u8]>,
) -> Result<T, BlsDoryAggregateError> {
    T::deserialize_with_mode(reader, Compress::Yes, Validate::Yes)
        .map_err(|_| BlsDoryAggregateError::InvalidEncoding)
}

fn read_cursor_u8(reader: &mut Cursor<&[u8]>) -> Result<u8, BlsDoryAggregateError> {
    let mut value = [0u8; 1];
    std::io::Read::read_exact(reader, &mut value)
        .map_err(|_| BlsDoryAggregateError::InvalidEncoding)?;
    Ok(value[0])
}

fn read_cursor_u32(reader: &mut Cursor<&[u8]>) -> Result<u32, BlsDoryAggregateError> {
    let mut value = [0u8; 4];
    std::io::Read::read_exact(reader, &mut value)
        .map_err(|_| BlsDoryAggregateError::InvalidEncoding)?;
    Ok(u32::from_le_bytes(value))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, BlsDoryAggregateError> {
    let value: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or(BlsDoryAggregateError::InvalidProofShape)?
        .try_into()
        .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    Ok(u16::from_le_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, BlsDoryAggregateError> {
    let value: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or(BlsDoryAggregateError::InvalidProofShape)?
        .try_into()
        .map_err(|_| BlsDoryAggregateError::InvalidProofShape)?;
    Ok(u32::from_le_bytes(value))
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::dory_bls12_381_prototype::deterministic_bls_dory_setup;

    static SCRATCH_NONCE: AtomicU64 = AtomicU64::new(1);

    struct ScratchDirectory(std::path::PathBuf);

    impl ScratchDirectory {
        fn create() -> Self {
            let nonce = SCRATCH_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cmfd-dory-aggregate-test-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for ScratchDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn benchmark_model_scalar(index: usize) -> BlsDoryFr {
        BlsDoryFr::from_u64(((index as u64 + 7) * 13 + 19) % 65_521)
    }

    fn serial_model_writer_reference(
        scratch_directory: &Path,
        explicit_count: usize,
        nu: usize,
        sigma: usize,
        setup: &DeterministicBlsDorySetup,
    ) -> BlsDoryCommittedPolynomial {
        let rows = 1usize << nu;
        let columns = 1usize << sigma;
        let spec =
            source_artifact_spec(setup.identity(), nu, sigma, rows * columns, explicit_count)
                .unwrap();
        let mut writer = BlsDoryFoldArtifactWriter::create(scratch_directory, spec).unwrap();
        let mut row_index = 0usize;
        let mut column_offset = 0usize;
        let mut current_row_commitment = BlsDoryG1::identity();
        let mut row_commitments = vec![BlsDoryG1::identity(); rows];
        let mut commitment = BlsDoryGt::identity();
        let scalar_chunk = 1usize << 16;
        for start in (0..explicit_count).step_by(scalar_chunk) {
            let end = start.saturating_add(scalar_chunk).min(explicit_count);
            let scalars = (start..end).map(benchmark_model_scalar).collect::<Vec<_>>();
            let mut remaining = scalars.as_slice();
            while !remaining.is_empty() {
                let take = remaining.len().min(columns - column_offset);
                let segment = &remaining[..take];
                current_row_commitment = current_row_commitment
                    + setup.commit_row_segment(column_offset, segment).unwrap();
                for scalar in segment {
                    writer.write_scalar(scalar).unwrap();
                }
                column_offset += take;
                remaining = &remaining[take..];
                if column_offset == columns {
                    commitment = commitment
                        + setup
                            .pair_committed_row(row_index, &current_row_commitment)
                            .unwrap();
                    row_commitments[row_index] = current_row_commitment;
                    row_index += 1;
                    column_offset = 0;
                    current_row_commitment = BlsDoryG1::identity();
                }
            }
        }
        if column_offset != 0 {
            commitment = commitment
                + setup
                    .pair_committed_row(row_index, &current_row_commitment)
                    .unwrap();
            row_commitments[row_index] = current_row_commitment;
        }
        let artifact = writer.finish().unwrap();
        BlsDoryCommittedPolynomial {
            coefficients: BlsDoryCoefficientStorage::AuthenticatedArtifact(Arc::new(artifact)),
            commitment,
            row_commitments,
            setup_identity: setup.identity(),
            nu,
            sigma,
        }
    }

    struct Fixture {
        setup: DeterministicBlsDorySetup,
        layout: BlsDoryAggregateLayout,
        polynomials: Vec<BlsDoryCommittedPolynomial>,
        points: Vec<Vec<BlsDoryFr>>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FixtureSourceError {
        Injected,
    }

    struct FixtureRowSource {
        rows: usize,
        columns: usize,
        coefficients: Vec<BlsDoryFr>,
        explicit_coefficients: usize,
        fail_at: Option<usize>,
        short_at: Option<usize>,
        reads: usize,
    }

    impl BlsDoryRowSource for FixtureRowSource {
        type Error = FixtureSourceError;

        fn rows(&self) -> usize {
            self.rows
        }

        fn columns(&self) -> usize {
            self.columns
        }

        fn explicit_scalar_count(&self) -> usize {
            self.explicit_coefficients
        }

        fn read_row(
            &mut self,
            row_index: usize,
            output: &mut [BlsDoryFr],
        ) -> Result<usize, Self::Error> {
            self.reads += 1;
            if self.fail_at == Some(row_index) {
                return Err(FixtureSourceError::Injected);
            }
            let start = row_index * self.columns;
            let end = start + self.columns;
            output.copy_from_slice(&self.coefficients[start..end]);
            Ok(if self.short_at == Some(row_index) {
                self.columns - 1
            } else {
                self.columns
            })
        }
    }

    fn fixture_row_source(variables: usize) -> FixtureRowSource {
        let rows = 1usize << (variables / 2);
        let columns = 1usize << (variables - variables / 2);
        FixtureRowSource {
            rows,
            columns,
            coefficients: (0..rows * columns)
                .map(|index| BlsDoryFr::from_u64(((index as u64 + 3) * 5 + 11) % 1_009))
                .collect(),
            explicit_coefficients: rows * columns,
            fail_at: None,
            short_at: None,
            reads: 0,
        }
    }

    struct FixtureCompactRowSource {
        rows: usize,
        columns: usize,
        explicit_coefficients: usize,
        word_coefficients: usize,
        word_group_len: usize,
        signed_word_selectors: u64,
        dictionary: Vec<BlsDoryFr>,
        tamper_first_code: bool,
    }

    impl BlsDoryCompactRowSource for FixtureCompactRowSource {
        type Error = FixtureSourceError;

        fn rows(&self) -> usize {
            self.rows
        }

        fn columns(&self) -> usize {
            self.columns
        }

        fn explicit_scalar_count(&self) -> usize {
            self.explicit_coefficients
        }

        fn word_scalar_count(&self) -> usize {
            self.word_coefficients
        }

        fn word_group_len(&self) -> usize {
            self.word_group_len
        }

        fn signed_word_selectors(&self) -> u64 {
            self.signed_word_selectors
        }

        fn dictionary(&self) -> &[BlsDoryFr] {
            &self.dictionary
        }

        fn read_word_row(
            &mut self,
            row_index: usize,
            output: &mut [u64],
        ) -> Result<usize, Self::Error> {
            if output.len() != self.columns || row_index >= self.word_coefficients / self.columns {
                return Err(FixtureSourceError::Injected);
            }
            for (column, word) in output.iter_mut().enumerate() {
                let packed_index = row_index * self.columns + column;
                let value = (packed_index + 17) as i64;
                *word = if compact_selector_is_signed(
                    packed_index / self.word_group_len,
                    self.signed_word_selectors,
                ) {
                    u64::from_le_bytes((-value).to_le_bytes())
                } else {
                    value as u64
                };
            }
            Ok(output.len())
        }

        fn read_code_row(
            &mut self,
            row_index: usize,
            output: &mut [u8],
        ) -> Result<usize, Self::Error> {
            let start = row_index * self.columns;
            if output.len() != self.columns
                || start < self.word_coefficients
                || start >= self.explicit_coefficients
            {
                return Err(FixtureSourceError::Injected);
            }
            for (column, code) in output.iter_mut().enumerate() {
                let index = start + column;
                *code = if index < self.explicit_coefficients {
                    (index % self.dictionary.len()) as u8
                } else {
                    0
                };
            }
            if self.tamper_first_code && start == self.word_coefficients {
                output[0] = (output[0] + 1) % self.dictionary.len() as u8;
            }
            Ok(output.len())
        }
    }

    fn fixture_compact_row_source(variables: usize) -> FixtureCompactRowSource {
        let rows = 1usize << (variables / 2);
        let columns = 1usize << (variables - variables / 2);
        FixtureCompactRowSource {
            rows,
            columns,
            explicit_coefficients: 6 * columns,
            word_coefficients: 2 * columns,
            word_group_len: columns,
            signed_word_selectors: 0,
            dictionary: (0..16).map(BlsDoryFr::from_u64).collect(),
            tamper_first_code: false,
        }
    }

    fn fixture_word_row_source(variables: usize) -> FixtureCompactRowSource {
        let rows = 1usize << (variables / 2);
        let columns = 1usize << (variables - variables / 2);
        FixtureCompactRowSource {
            rows,
            columns,
            explicit_coefficients: rows * columns,
            word_coefficients: rows * columns,
            word_group_len: columns,
            signed_word_selectors: 0,
            dictionary: vec![BlsDoryFr::zero()],
            tamper_first_code: false,
        }
    }

    fn collect_authenticated_range(
        polynomial: &BlsDoryCommittedPolynomial,
        start: usize,
        count: usize,
    ) -> Result<Vec<(usize, BlsDoryFr)>, BlsDoryAggregateError> {
        let mut values = Vec::with_capacity(count);
        polynomial.for_each_authenticated_coefficient_range(
            start,
            count,
            |index, coefficient| {
                values.push((index, coefficient));
                Ok(())
            },
        )?;
        Ok(values)
    }

    fn assert_authenticated_range(
        polynomial: &BlsDoryCommittedPolynomial,
        expected: &[BlsDoryFr],
        start: usize,
        count: usize,
    ) {
        let actual = collect_authenticated_range(polynomial, start, count).unwrap();
        assert_eq!(
            actual.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
            (start..start + count).collect::<Vec<_>>()
        );
        assert_eq!(
            actual
                .into_iter()
                .map(|(_, coefficient)| coefficient)
                .collect::<Vec<_>>(),
            expected[start..start + count]
        );
    }

    #[test]
    fn bounded_signed_dictionary_has_canonical_codes_and_rejects_out_of_range_values() {
        let dictionary = bounded_signed_dictionary(125).unwrap();
        assert_eq!(dictionary.len(), 251);
        assert!(is_bounded_signed_dictionary(&dictionary));
        for value in -125..=125 {
            let code = bounded_signed_code(value, 125).unwrap();
            assert_eq!(dictionary[usize::from(code)], BlsDoryFr::from_i64(value));
        }
        assert_eq!(bounded_signed_code(-126, 125), None);
        assert_eq!(bounded_signed_code(126, 125), None);
        assert_eq!(bounded_signed_dictionary(0), None);

        let mut reordered = dictionary;
        reordered.swap(1, 2);
        assert!(!is_bounded_signed_dictionary(&reordered));
    }

    fn fixture(variables: usize, claims: usize) -> Fixture {
        let setup = deterministic_bls_dory_setup(variables).unwrap();
        let nu = variables / 2;
        let sigma = variables - nu;
        let coefficient_count = 1usize << variables;
        let polynomials = (0..claims)
            .map(|claim| {
                let coefficients = (0..coefficient_count)
                    .map(|index| {
                        BlsDoryFr::from_u64(((index as u64 + 3) * (claim as u64 + 5) + 11) % 1_009)
                    })
                    .collect();
                commit_bls_dory_polynomial(coefficients, nu, sigma, &setup).unwrap()
            })
            .collect();
        let points = (0..claims)
            .map(|claim| {
                (0..variables)
                    .map(|coordinate| {
                        BlsDoryFr::from_u64((claim as u64 + 2) * (coordinate as u64 + 7))
                    })
                    .collect()
            })
            .collect();
        Fixture {
            setup,
            layout: BlsDoryAggregateLayout::new(nu, sigma).unwrap(),
            polynomials,
            points,
        }
    }

    fn test_layout(variables: usize) -> BlsDoryAggregateLayout {
        BlsDoryAggregateLayout::new(variables / 2, variables - variables / 2).unwrap()
    }

    #[test]
    fn distinct_points_reduce_to_one_real_bls_opening() {
        let Fixture {
            setup,
            layout,
            polynomials,
            points,
        } = fixture(8, 3);
        let (claims, proof) =
            prove_bls_dory_openings(b"block-binding", layout, &polynomials, &points, &setup)
                .unwrap();
        verify_bls_dory_openings(b"block-binding", layout, &claims, &proof, &setup).unwrap();
        assert_eq!(
            blake3::hash(&proof).to_hex().as_str(),
            "6aa99fd095e70180b6b2fdd94dc96fc420f99eb529ec03ad5dfa978731d9cfac"
        );
        assert_eq!(proof.len(), aggregate_wire_bytes(8, 4));
        assert_eq!(proof.len(), 17_695);
        assert!(proof.len() < MAX_BLS_DORY_AGGREGATE_BYTES);
    }

    #[test]
    fn composed_claim_limit_accepts_exactly_134_without_widening_public_boundary() {
        let variables = 4;
        let setup = deterministic_bls_dory_setup(variables).unwrap();
        let layout = test_layout(variables);
        let polynomial = commit_bls_dory_polynomial(
            (0..1usize << variables)
                .map(|index| BlsDoryFr::from_u64(index as u64 + 1))
                .collect(),
            layout.nu,
            layout.sigma,
            &setup,
        )
        .unwrap();
        let points = (0..BLS_DORY_COMPOSED_AGGREGATE_CLAIMS)
            .map(|claim| {
                (0..variables)
                    .map(|coordinate| {
                        BlsDoryFr::from_u64((claim as u64 + 2) * (coordinate as u64 + 3) + 5)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        assert_eq!(MAX_BLS_DORY_AGGREGATE_CLAIMS, 128);
        assert_eq!(BLS_DORY_COMPOSED_AGGREGATE_CLAIMS, 134);
        assert_eq!(
            prove_bls_dory_same_commitment_openings(
                b"test-claim-limit",
                layout,
                &polynomial,
                &points,
                &setup,
            ),
            Err(BlsDoryAggregateError::InvalidClaimCount)
        );

        let (claims, proof) = prove_bls_dory_same_commitment_openings_with_test_claim_limit(
            b"test-claim-limit",
            layout,
            &polynomial,
            &points,
            &setup,
        )
        .unwrap();
        assert_eq!(claims.len(), BLS_DORY_COMPOSED_AGGREGATE_CLAIMS);
        assert_eq!(
            read_u16(&proof, 10).unwrap() as usize,
            BLS_DORY_COMPOSED_AGGREGATE_CLAIMS
        );
        verify_bls_dory_composed_openings(b"test-claim-limit", layout, &claims, &proof, &setup)
            .unwrap();
        assert_eq!(
            verify_bls_dory_openings(b"test-claim-limit", layout, &claims, &proof, &setup,),
            Err(BlsDoryAggregateError::InvalidClaimCount)
        );

        let mut changed_count = proof.clone();
        changed_count[10..12].copy_from_slice(&133u16.to_le_bytes());
        assert_eq!(
            verify_bls_dory_composed_openings(
                b"test-claim-limit",
                layout,
                &claims,
                &changed_count,
                &setup,
            ),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );
        let mut changed_count = proof.clone();
        changed_count[10..12].copy_from_slice(&135u16.to_le_bytes());
        assert_eq!(
            verify_bls_dory_composed_openings(
                b"test-claim-limit",
                layout,
                &claims,
                &changed_count,
                &setup,
            ),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );
        assert_eq!(
            verify_bls_dory_composed_openings(
                b"test-claim-limit",
                layout,
                &claims[..133],
                &proof,
                &setup,
            ),
            Err(BlsDoryAggregateError::InvalidClaimCount)
        );

        let mut too_many_points = points;
        too_many_points.push(vec![BlsDoryFr::from_u64(1); variables]);
        assert_eq!(
            prove_bls_dory_same_commitment_openings_with_test_claim_limit(
                b"test-claim-limit",
                layout,
                &polynomial,
                &too_many_points,
                &setup,
            ),
            Err(BlsDoryAggregateError::InvalidClaimCount)
        );
        let mut too_many_claims = claims;
        too_many_claims.push(too_many_claims[0].clone());
        assert_eq!(
            verify_bls_dory_composed_openings(
                b"test-claim-limit",
                layout,
                &too_many_claims,
                &proof,
                &setup,
            ),
            Err(BlsDoryAggregateError::InvalidClaimCount)
        );
    }

    #[test]
    fn repeated_claims_share_one_folded_polynomial_table() {
        let Fixture {
            setup,
            layout,
            polynomials,
            points,
        } = fixture(6, 3);
        let polynomial = &polynomials[0];
        let polynomial_refs = vec![polynomial, polynomial, polynomial];
        let claims = points
            .iter()
            .map(|point| BlsDoryOpeningClaim {
                commitment: polynomial.commitment,
                point: point.clone(),
                evaluation: polynomial.evaluate(point).unwrap(),
            })
            .collect::<Vec<_>>();
        let mut transcript =
            statement_transcript(b"deduplicated-folds", &setup.identity(), &claims, 3, 3).unwrap();
        let batching = batching_challenges(&mut transcript, claims.len());

        let sumcheck = prove_distinct_point_sumcheck(
            &polynomial_refs,
            &claims,
            &batching,
            &mut transcript,
            None,
        )
        .unwrap();

        assert_eq!(sumcheck.unique_polynomial_tables, 1);
        assert_eq!(sumcheck.peak_additional_coefficients, 1 << 5);
        let (public_claims, proof) = prove_bls_dory_opening_refs_with_scratch(
            b"deduplicated-folds",
            layout,
            &polynomial_refs,
            &points,
            &setup,
            None,
        )
        .unwrap();
        verify_bls_dory_openings(
            b"deduplicated-folds",
            layout,
            &public_claims,
            &proof,
            &setup,
        )
        .unwrap();
    }

    #[test]
    fn authenticated_scratch_preserves_exact_proof_bytes_and_cleans_artifacts() {
        let Fixture {
            setup,
            layout,
            polynomials,
            points,
        } = fixture(6, 3);
        let scratch = ScratchDirectory::create();
        let ordinary = prove_bls_dory_openings(
            b"scratch-equivalence",
            layout,
            &polynomials,
            &points,
            &setup,
        )
        .unwrap();
        let artifact_backed = prove_bls_dory_openings_with_scratch(
            b"scratch-equivalence",
            layout,
            &polynomials,
            &points,
            &setup,
            &scratch.0,
        )
        .unwrap();

        assert_eq!(artifact_backed, ordinary);
        verify_bls_dory_openings(
            b"scratch-equivalence",
            layout,
            &artifact_backed.0,
            &artifact_backed.1,
            &setup,
        )
        .unwrap();
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
        assert_eq!(
            prove_bls_dory_openings_with_scratch(
                b"scratch-equivalence",
                layout,
                &polynomials,
                &points,
                &setup,
                Path::new("relative-scratch"),
            ),
            Err(BlsDoryAggregateError::ProverStorage)
        );
    }

    #[test]
    fn authenticated_row_source_preserves_commitment_and_exact_proof_bytes() {
        let variables = 8;
        let nu = variables / 2;
        let sigma = variables - nu;
        let setup = deterministic_bls_dory_setup(variables).unwrap();
        let scratch = ScratchDirectory::create();
        let mut source = fixture_row_source(variables);
        let materialized =
            commit_bls_dory_polynomial(source.coefficients.clone(), nu, sigma, &setup).unwrap();
        let artifact_backed =
            commit_bls_dory_row_source_with_scratch(&mut source, nu, sigma, &setup, &scratch.0)
                .unwrap();
        assert_eq!(source.reads, source.rows);
        assert_eq!(artifact_backed.commitment, materialized.commitment);
        assert_eq!(
            artifact_backed.row_commitments,
            materialized.row_commitments
        );
        assert!(artifact_backed.materialized_coefficients().is_none());
        assert!(
            artifact_backed
                .coefficient_artifact_path()
                .unwrap()
                .is_file()
        );

        let points = vec![
            (0..variables)
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 2) * 7))
                .collect::<Vec<_>>(),
            (0..variables)
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 3) * 11))
                .collect::<Vec<_>>(),
        ];
        let ordinary = prove_bls_dory_same_commitment_openings(
            b"row-source-equivalence",
            test_layout(variables),
            &materialized,
            &points,
            &setup,
        )
        .unwrap();
        let artifact_refs = vec![&artifact_backed; points.len()];
        let streamed = prove_bls_dory_opening_refs_with_scratch(
            b"row-source-equivalence",
            test_layout(variables),
            &artifact_refs,
            &points,
            &setup,
            Some(&scratch.0),
        )
        .unwrap();
        assert_eq!(streamed, ordinary);
        verify_bls_dory_openings(
            b"row-source-equivalence",
            test_layout(variables),
            &streamed.0,
            &streamed.1,
            &setup,
        )
        .unwrap();
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 1);

        let clone = artifact_backed.clone();
        assert!(artifact_backed.shares_coefficient_source(&clone));
        let cloned_refs = vec![&artifact_backed, &clone];
        let mut transcript = statement_transcript(
            b"row-source-equivalence",
            &setup.identity(),
            &streamed.0,
            nu,
            sigma,
        )
        .unwrap();
        let batching = batching_challenges(&mut transcript, streamed.0.len());
        let sumcheck = prove_distinct_point_sumcheck(
            &cloned_refs,
            &streamed.0,
            &batching,
            &mut transcript,
            None,
        )
        .unwrap();
        assert_eq!(sumcheck.unique_polynomial_tables, 1);
        let cloned = prove_bls_dory_opening_refs_with_scratch(
            b"row-source-equivalence",
            test_layout(variables),
            &cloned_refs,
            &points,
            &setup,
            Some(&scratch.0),
        )
        .unwrap();
        assert_eq!(cloned, streamed);
        let artifact_path = artifact_backed
            .coefficient_artifact_path()
            .unwrap()
            .to_path_buf();
        drop(artifact_backed);
        assert!(artifact_path.is_file());
        drop(clone);
        assert!(!artifact_path.exists());
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn authenticated_ranges_preserve_dense_fold_compact_and_mapped_order() {
        let variables = 6;
        let nu = variables / 2;
        let sigma = variables - nu;
        let total = 1usize << variables;
        let setup = deterministic_bls_dory_setup(variables).unwrap();
        let scratch = ScratchDirectory::create();

        let mut fold_source = fixture_row_source(variables);
        fold_source.explicit_coefficients -= 2 * fold_source.columns;
        let fold_explicit = fold_source.explicit_coefficients;
        let mut fold_expected = fold_source.coefficients[..fold_explicit].to_vec();
        fold_expected.resize(total, BlsDoryFr::zero());
        let dense = commit_bls_dory_polynomial(fold_expected.clone(), nu, sigma, &setup).unwrap();
        let fold = commit_bls_dory_row_source_with_scratch(
            &mut fold_source,
            nu,
            sigma,
            &setup,
            &scratch.0,
        )
        .unwrap();
        let fold_start = fold_explicit - 3;
        assert_authenticated_range(&dense, &fold_expected, fold_start, 9);
        assert_authenticated_range(&fold, &fold_expected, fold_start, 9);

        let mut compact_source = fixture_compact_row_source(variables);
        let compact_explicit = compact_source.explicit_coefficients;
        let word_count = compact_source.word_coefficients;
        let compact = commit_bls_dory_compact_row_source_with_scratch(
            &mut compact_source,
            nu,
            sigma,
            &setup,
            &scratch.0,
        )
        .unwrap();
        let mapped_dictionary = (0..16)
            .map(|digit| BlsDoryFr::from_u64(digit + 101))
            .collect::<Vec<_>>();
        let mapped = commit_bls_dory_mapped_compact_polynomial(
            &compact,
            word_count,
            mapped_dictionary.clone(),
            &setup,
        )
        .unwrap();
        let compact_expected = (0..total)
            .map(|index| {
                if index < word_count {
                    BlsDoryFr::from_u64(index as u64 + 17)
                } else if index < compact_explicit {
                    BlsDoryFr::from_u64((index % 16) as u64)
                } else {
                    BlsDoryFr::zero()
                }
            })
            .collect::<Vec<_>>();
        let mapped_expected = (0..total)
            .map(|index| {
                if index < word_count || index >= compact_explicit {
                    BlsDoryFr::zero()
                } else {
                    mapped_dictionary[index % mapped_dictionary.len()]
                }
            })
            .collect::<Vec<_>>();
        for (start, count) in [
            (word_count - 2, 8),
            (compact_explicit - 2, total - compact_explicit + 2),
        ] {
            assert_authenticated_range(&compact, &compact_expected, start, count);
            assert_authenticated_range(&mapped, &mapped_expected, start, count);
        }

        drop(fold);
        drop(mapped);
        drop(compact);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn authenticated_ranges_propagate_callback_errors_and_reject_invalid_bounds() {
        let variables = 6;
        let setup = deterministic_bls_dory_setup(variables).unwrap();
        let scratch = ScratchDirectory::create();
        let mut source = fixture_row_source(variables);
        let polynomial = commit_bls_dory_row_source_with_scratch(
            &mut source,
            variables / 2,
            variables - variables / 2,
            &setup,
            &scratch.0,
        )
        .unwrap();
        let total = 1usize << variables;

        let mut exposed = 0usize;
        assert_eq!(
            polynomial.for_each_authenticated_coefficient_range(4, 12, |_index, _coefficient| {
                exposed += 1;
                if exposed == 3 {
                    Err(BlsDoryAggregateError::SumcheckFailed)
                } else {
                    Ok(())
                }
            }),
            Err(BlsDoryAggregateError::SumcheckFailed)
        );
        assert_eq!(exposed, 3);

        for (start, count) in [
            (total, 1),
            (usize::MAX, 2),
            (0, MAX_AUTHENTICATED_COEFFICIENT_RANGE_SCALARS + 1),
        ] {
            let mut called = false;
            assert_eq!(
                polynomial.for_each_authenticated_coefficient_range(
                    start,
                    count,
                    |_index, _coefficient| {
                        called = true;
                        Ok(())
                    },
                ),
                Err(BlsDoryAggregateError::InvalidCoefficientCount)
            );
            assert!(!called);
        }
        assert!(
            collect_authenticated_range(&polynomial, total, 0)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn corrupted_artifact_range_fails_before_exposing_a_coefficient_and_cleans_up() {
        let variables = 6;
        let setup = deterministic_bls_dory_setup(variables).unwrap();
        let scratch = ScratchDirectory::create();
        let mut source = fixture_row_source(variables);
        let polynomial = commit_bls_dory_row_source_with_scratch(
            &mut source,
            variables / 2,
            variables - variables / 2,
            &setup,
            &scratch.0,
        )
        .unwrap();
        let path = polynomial
            .coefficient_artifact_path()
            .unwrap()
            .to_path_buf();
        let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let offset = std::fs::metadata(&path).unwrap().len() - 1;
        let replacement = std::fs::read(&path).unwrap()[usize::try_from(offset).unwrap()] ^ 1;
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&[replacement]).unwrap();
        file.flush().unwrap();
        drop(file);

        let mut exposed = 0usize;
        assert_eq!(
            polynomial.for_each_authenticated_coefficient_range(3, 7, |_index, _coefficient| {
                exposed += 1;
                Ok(())
            }),
            Err(BlsDoryAggregateError::ProverStorage)
        );
        assert_eq!(exposed, 0);
        drop(polynomial);
        assert!(!path.exists());
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn existing_compact_artifact_commit_matches_source_path_and_fails_closed() {
        let variables = 7;
        let nu = variables / 2;
        let sigma = variables - nu;
        let setup = deterministic_bls_dory_setup(variables).unwrap();
        let scratch = ScratchDirectory::create();
        let mut source = fixture_compact_row_source(variables);
        source.explicit_coefficients -= 3;
        let streamed = commit_bls_dory_compact_row_source_with_scratch(
            &mut source,
            nu,
            sigma,
            &setup,
            &scratch.0,
        )
        .unwrap();
        let artifact = match &streamed.coefficients {
            BlsDoryCoefficientStorage::CompactArtifact(artifact) => Arc::clone(artifact),
            _ => panic!("compact source must retain its finished artifact"),
        };
        let path = artifact.path().to_path_buf();
        let original_file = std::fs::read(&path).unwrap();
        let retained_identity = BlsDoryReleasedCompactSource::from_artifact(&artifact);
        retained_identity.validate_artifact(&artifact).unwrap();
        let mut wrong_spec = retained_identity.clone();
        wrong_spec.spec.context_digest[0] ^= 1;
        assert_eq!(
            wrong_spec.validate_artifact(&artifact),
            Err(BlsDoryAggregateError::ProverStorage)
        );
        let mut wrong_dictionary = retained_identity.clone();
        wrong_dictionary.dictionary[0] = BlsDoryFr::from_u64(999);
        assert_eq!(
            wrong_dictionary.validate_artifact(&artifact),
            Err(BlsDoryAggregateError::ProverStorage)
        );
        let mut wrong_digest = retained_identity;
        wrong_digest.digest[0] ^= 1;
        assert_eq!(
            wrong_digest.validate_artifact(&artifact),
            Err(BlsDoryAggregateError::ProverStorage)
        );

        let existing =
            commit_bls_dory_existing_compact_artifact(Arc::clone(&artifact), nu, sigma, &setup)
                .unwrap();
        assert_eq!(existing.commitment, streamed.commitment);
        assert_eq!(existing.row_commitments, streamed.row_commitments);
        match &existing.coefficients {
            BlsDoryCoefficientStorage::CompactArtifact(existing_artifact) => {
                assert!(Arc::ptr_eq(existing_artifact, &artifact));
            }
            _ => panic!("existing artifact commit must retain the same compact source"),
        }
        assert_eq!(std::fs::read(&path).unwrap(), original_file);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 1);

        let encode_coefficients = |polynomial: &BlsDoryCommittedPolynomial| {
            let mut encoded = Vec::new();
            polynomial
                .for_each_explicit_coefficient(|_index, coefficient| {
                    append_serialized(&mut encoded, &coefficient).unwrap();
                })
                .unwrap();
            encoded
        };
        assert_eq!(
            encode_coefficients(&existing),
            encode_coefficients(&streamed)
        );
        let point = (0..variables)
            .map(|index| BlsDoryFr::from_u64(index as u64 + 23))
            .collect::<Vec<_>>();
        let streamed_opening = prove_bls_dory_opening_refs_with_scratch(
            b"existing-compact-artifact",
            test_layout(variables),
            &[&streamed],
            std::slice::from_ref(&point),
            &setup,
            Some(&scratch.0),
        )
        .unwrap();
        let existing_opening = prove_bls_dory_opening_refs_with_scratch(
            b"existing-compact-artifact",
            test_layout(variables),
            &[&existing],
            &[point],
            &setup,
            Some(&scratch.0),
        )
        .unwrap();
        assert_eq!(existing_opening, streamed_opening);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 1);

        let wrong_setup = deterministic_bls_dory_setup(variables + 1).unwrap();
        assert!(matches!(
            commit_bls_dory_existing_compact_artifact(
                Arc::clone(&artifact),
                nu,
                sigma,
                &wrong_setup,
            ),
            Err(BlsDoryAggregateError::ProverStorage)
        ));
        assert!(matches!(
            commit_bls_dory_existing_compact_artifact(
                Arc::clone(&artifact),
                nu - 1,
                sigma + 1,
                &setup,
            ),
            Err(BlsDoryAggregateError::ProverStorage)
        ));

        let offset = u64::try_from(original_file.len() - 1).unwrap();
        let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&[original_file[original_file.len() - 1] ^ 1])
            .unwrap();
        file.flush().unwrap();
        drop(file);
        assert!(matches!(
            commit_bls_dory_existing_compact_artifact(Arc::clone(&artifact), nu, sigma, &setup,),
            Err(BlsDoryAggregateError::ProverStorage)
        ));

        drop(existing);
        drop(streamed);
        assert!(path.exists());
        drop(artifact);
        assert!(!path.exists());
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn compact_source_release_regenerates_exact_bytes_and_rejects_substitution() {
        let variables = 6;
        let nu = variables / 2;
        let sigma = variables - nu;
        let setup = deterministic_bls_dory_setup(variables).unwrap();
        let scratch = ScratchDirectory::create();
        let mut source = fixture_compact_row_source(variables);
        let compact = commit_bls_dory_compact_row_source_with_scratch(
            &mut source,
            nu,
            sigma,
            &setup,
            &scratch.0,
        )
        .unwrap();
        let mapped = commit_bls_dory_mapped_compact_polynomial(
            &compact,
            source.word_coefficients,
            (0..16)
                .map(|index| BlsDoryFr::from_u64(index + 101))
                .collect(),
            &setup,
        )
        .unwrap();
        let points = vec![
            (0..variables)
                .map(|index| BlsDoryFr::from_u64(index as u64 + 3))
                .collect::<Vec<_>>(),
            (0..variables)
                .map(|index| BlsDoryFr::from_u64(index as u64 + 29))
                .collect::<Vec<_>>(),
        ];
        let mut openings =
            BlsDoryDeferredOpeningSet::new(vec![compact, mapped], vec![0, 1], points).unwrap();
        let original = prove_bls_dory_deferred_opening_sets(
            b"compact-release",
            test_layout(variables),
            &[&openings],
            &setup,
        )
        .unwrap();
        let original_prefixes = [0, 1].map(|index| {
            collect_authenticated_range(openings.polynomial(index).unwrap(), 5, 11).unwrap()
        });
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 1);

        let identity = openings.release_compact_source().unwrap().unwrap();
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
        for index in [0, 1] {
            let mut exposed = 0usize;
            assert_eq!(
                openings
                    .polynomial(index)
                    .unwrap()
                    .for_each_authenticated_coefficient_range(
                        5,
                        11,
                        |_coefficient_index, _coefficient| {
                            exposed += 1;
                            Ok(())
                        },
                    ),
                Err(BlsDoryAggregateError::ProverStorage)
            );
            assert_eq!(exposed, 0);
        }
        assert_eq!(
            openings
                .polynomial(0)
                .unwrap()
                .evaluate(&original.0[0].point),
            Err(BlsDoryAggregateError::ProverStorage)
        );

        let mut substituted = fixture_compact_row_source(variables);
        substituted.tamper_first_code = true;
        assert!(matches!(
            regenerate_bls_dory_compact_row_source_with_scratch(
                &mut substituted,
                &identity,
                nu,
                sigma,
                &setup,
                &scratch.0,
            ),
            Err(BlsDoryAggregateError::ProverStorage)
        ));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);

        let mut regenerated_source = fixture_compact_row_source(variables);
        let regenerated = regenerate_bls_dory_compact_row_source_with_scratch(
            &mut regenerated_source,
            &identity,
            nu,
            sigma,
            &setup,
            &scratch.0,
        )
        .unwrap();
        let regenerated_path = regenerated.path().to_path_buf();
        openings.restore_compact_source(&regenerated).unwrap();
        assert_eq!(
            openings.restore_compact_source(&regenerated),
            Err(BlsDoryAggregateError::ProverStorage)
        );
        let restored = prove_bls_dory_deferred_opening_sets(
            b"compact-release",
            test_layout(variables),
            &[&openings],
            &setup,
        )
        .unwrap();
        assert_eq!(restored, original);
        for (index, expected) in original_prefixes.iter().enumerate() {
            assert_eq!(
                collect_authenticated_range(openings.polynomial(index).unwrap(), 5, 11).unwrap(),
                *expected
            );
        }
        drop(regenerated);
        assert!(regenerated_path.exists());
        drop(openings);
        assert!(!regenerated_path.exists());
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn paired_compact_aggregate_folds_preserve_exact_proof_bytes() {
        let variables = 8;
        let nu = variables / 2;
        let sigma = variables - nu;
        let setup = deterministic_bls_dory_setup(variables).unwrap();
        let scratch = ScratchDirectory::create();
        let mut source = fixture_compact_row_source(variables);
        let compact = commit_bls_dory_compact_row_source_with_scratch(
            &mut source,
            nu,
            sigma,
            &setup,
            &scratch.0,
        )
        .unwrap();
        let mapped = commit_bls_dory_mapped_compact_polynomial(
            &compact,
            source.word_coefficients,
            (0..16)
                .map(|digit| BlsDoryFr::from_u64(digit + 101))
                .collect(),
            &setup,
        )
        .unwrap();
        let points = vec![
            (0..variables)
                .map(|index| BlsDoryFr::from_u64(index as u64 + 5))
                .collect::<Vec<_>>(),
            (0..variables)
                .map(|index| BlsDoryFr::from_u64(index as u64 + 31))
                .collect::<Vec<_>>(),
        ];
        let polynomial_refs = vec![&compact, &mapped];
        let ordinary = prove_bls_dory_opening_refs_with_scratch(
            b"paired-compact-folds",
            test_layout(variables),
            &polynomial_refs,
            &points,
            &setup,
            None,
        )
        .unwrap();

        let mut transcript = statement_transcript(
            b"paired-compact-folds",
            &setup.identity(),
            &ordinary.0,
            nu,
            sigma,
        )
        .unwrap();
        let batching = batching_challenges(&mut transcript, ordinary.0.len());
        let fold_scratch = FoldScratch::new(&scratch.0, [9; 32]).unwrap();
        let sumcheck = prove_distinct_point_sumcheck(
            &polynomial_refs,
            &ordinary.0,
            &batching,
            &mut transcript,
            Some(&fold_scratch),
        )
        .unwrap();
        assert_eq!(sumcheck.compressed_pair_count, 1);
        assert_eq!(sumcheck.compressed_pair_folds, 8);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 1);

        let compressed = prove_bls_dory_opening_refs_with_scratch(
            b"paired-compact-folds",
            test_layout(variables),
            &polynomial_refs,
            &points,
            &setup,
            Some(&scratch.0),
        )
        .unwrap();
        assert_eq!(compressed, ordinary);
        verify_bls_dory_openings(
            b"paired-compact-folds",
            test_layout(variables),
            &compressed.0,
            &compressed.1,
            &setup,
        )
        .unwrap();
        drop(mapped);
        drop(compact);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn word_compact_aggregate_folds_preserve_proof_bytes_and_bind_lineage() {
        let variables = 8;
        let nu = variables / 2;
        let sigma = variables - nu;
        let setup = deterministic_bls_dory_setup(variables).unwrap();
        let scratch = ScratchDirectory::create();
        let coefficients = (0..1usize << variables)
            .map(|index| BlsDoryFr::from_u64(index as u64 + 17))
            .collect::<Vec<_>>();
        let dense = commit_bls_dory_polynomial(coefficients, nu, sigma, &setup).unwrap();
        let mut source = fixture_word_row_source(variables);
        let compact = commit_bls_dory_compact_row_source_with_scratch(
            &mut source,
            nu,
            sigma,
            &setup,
            &scratch.0,
        )
        .unwrap();
        assert_eq!(compact.commitment(), dense.commitment());
        let point = (0..variables)
            .map(|index| BlsDoryFr::from_u64(index as u64 + 29))
            .collect::<Vec<_>>();
        let dense_result = prove_bls_dory_opening_refs_with_scratch(
            b"word-compact-folds",
            test_layout(variables),
            &[&dense],
            std::slice::from_ref(&point),
            &setup,
            None,
        )
        .unwrap();
        let compact_result = prove_bls_dory_opening_refs_with_scratch(
            b"word-compact-folds",
            test_layout(variables),
            &[&compact],
            &[point],
            &setup,
            Some(&scratch.0),
        )
        .unwrap();
        assert_eq!(compact_result, dense_result);

        let mut table = FoldedPolynomialTable::source(&compact, 0).unwrap();
        fold_aggregate_word_table(&mut table, BlsDoryFr::from_u64(31), 1).unwrap();
        table.lineage_digest[0] ^= 1;
        assert_eq!(
            table.for_each_pair(|_, _| {}),
            Err(BlsDoryAggregateError::ProverStorage)
        );
        drop(table);
        drop(compact);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn wide_signed_word_compact_folds_preserve_scratch_proof_bytes() {
        let variables = 8;
        let nu = variables / 2;
        let sigma = variables - nu;
        let rows = 1usize << nu;
        let columns = 1usize << sigma;
        let setup = deterministic_bls_dory_setup(variables).unwrap();
        let scratch = ScratchDirectory::create();
        let coefficients = (0..rows * columns)
            .map(|index| BlsDoryFr::from_i64(-((index + 17) as i64)))
            .collect::<Vec<_>>();
        let dense = commit_bls_dory_polynomial(coefficients, nu, sigma, &setup).unwrap();
        let mut source = FixtureCompactRowSource {
            rows,
            columns,
            explicit_coefficients: rows * columns,
            word_coefficients: rows * columns,
            word_group_len: 1,
            signed_word_selectors: u64::MAX,
            dictionary: vec![BlsDoryFr::zero()],
            tamper_first_code: false,
        };
        let compact = commit_bls_dory_compact_row_source_with_scratch(
            &mut source,
            nu,
            sigma,
            &setup,
            &scratch.0,
        )
        .unwrap();
        assert_eq!(compact.commitment(), dense.commitment());
        let point = (0..variables)
            .map(|index| BlsDoryFr::from_u64(index as u64 + 41))
            .collect::<Vec<_>>();
        let dense_result = prove_bls_dory_opening_refs_with_scratch(
            b"wide-signed-word-compact-folds",
            test_layout(variables),
            &[&dense],
            std::slice::from_ref(&point),
            &setup,
            None,
        )
        .unwrap();
        let compact_result = prove_bls_dory_opening_refs_with_scratch(
            b"wide-signed-word-compact-folds",
            test_layout(variables),
            &[&compact],
            &[point],
            &setup,
            Some(&scratch.0),
        )
        .unwrap();
        assert_eq!(compact_result, dense_result);
        verify_bls_dory_openings(
            b"wide-signed-word-compact-folds",
            test_layout(variables),
            &compact_result.0,
            &compact_result.1,
            &setup,
        )
        .unwrap();
        drop(compact);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn corrupted_paired_compact_source_aborts_and_cleans_scratch() {
        let variables = 8;
        let nu = variables / 2;
        let sigma = variables - nu;
        let setup = deterministic_bls_dory_setup(variables).unwrap();
        let scratch = ScratchDirectory::create();
        let mut source = fixture_compact_row_source(variables);
        let compact = commit_bls_dory_compact_row_source_with_scratch(
            &mut source,
            nu,
            sigma,
            &setup,
            &scratch.0,
        )
        .unwrap();
        let mapped = commit_bls_dory_mapped_compact_polynomial(
            &compact,
            source.word_coefficients,
            (0..16)
                .map(|digit| BlsDoryFr::from_u64(digit + 211))
                .collect(),
            &setup,
        )
        .unwrap();
        let polynomial_refs = vec![&compact, &mapped];
        let pairs = find_aggregate_compact_pairs(&polynomial_refs);
        assert_eq!(pairs.len(), 1);
        let mut tables = polynomial_refs
            .iter()
            .enumerate()
            .map(|(table_index, polynomial)| FoldedPolynomialTable::source(polynomial, table_index))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let fold_scratch = FoldScratch::new(&scratch.0, [7; 32]).unwrap();
        fold_aggregate_compact_pair(
            &mut tables,
            &pairs[0],
            BlsDoryFr::from_u64(23),
            1,
            &fold_scratch,
        )
        .unwrap();
        let FoldedPolynomialStorage::Compact(view) = &tables[pairs[0].transition_table].storage
        else {
            panic!("transition table must use the shared compressed fold");
        };
        let source_path = view.source.path().to_path_buf();
        let transition_lineage = tables[pairs[0].transition_table].lineage_digest;
        tables[pairs[0].transition_table].lineage_digest =
            tables[pairs[0].mapped_table].lineage_digest;
        assert_eq!(
            tables[pairs[0].transition_table].for_each_pair(|_, _| {}),
            Err(BlsDoryAggregateError::ProverStorage)
        );
        tables[pairs[0].transition_table].lineage_digest = transition_lineage;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&source_path)
            .unwrap();
        file.seek(SeekFrom::Start(12)).unwrap();
        file.write_all(&[0xa5]).unwrap();
        file.flush().unwrap();
        assert_eq!(
            tables[pairs[0].transition_table].for_each_pair(|_, _| {}),
            Err(BlsDoryAggregateError::ProverStorage)
        );
        drop(file);
        drop(tables);
        assert!(source_path.exists());
        drop(pairs);
        drop(polynomial_refs);
        drop(mapped);
        drop(compact);
        assert!(!source_path.exists());
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn chunked_polynomial_writer_matches_row_source_and_exact_proof_bytes() {
        let variables = 8;
        let nu = variables / 2;
        let sigma = variables - nu;
        let columns = 1usize << sigma;
        let explicit = 1usize << (variables - 1);
        let setup = deterministic_bls_dory_setup(variables).unwrap();
        let coefficients = (0..(1usize << variables))
            .map(|index| BlsDoryFr::from_u64((index as u64 + 5) * 17))
            .collect::<Vec<_>>();
        let first_scratch = ScratchDirectory::create();
        let second_scratch = ScratchDirectory::create();
        let chunk_bytes = 2 * columns * std::mem::size_of::<BlsDoryFr>();
        let mut writer = BlsDoryCommittedPolynomialWriter::create_with_chunk_bytes(
            &first_scratch.0,
            explicit,
            nu,
            sigma,
            &setup,
            chunk_bytes,
        )
        .unwrap();
        assert_eq!(writer.pending_capacity, 2 * columns);
        let mut offset = 0usize;
        for chunk_len in [3usize, 29, 1, 47, 11, 37] {
            writer
                .write_scalars(&coefficients[offset..offset + chunk_len])
                .unwrap();
            offset += chunk_len;
            assert!(writer.pending_scalars.len() < writer.pending_capacity);
        }
        assert_eq!(offset, explicit);
        assert_eq!(writer.pending_scalars.capacity(), 0);
        let chunked = writer.finish().unwrap();

        let mut source = fixture_row_source(variables);
        source.coefficients = coefficients;
        source.explicit_coefficients = explicit;
        let streamed = commit_bls_dory_row_source_with_scratch(
            &mut source,
            nu,
            sigma,
            &setup,
            &second_scratch.0,
        )
        .unwrap();
        assert_eq!(chunked.commitment, streamed.commitment);
        assert_eq!(chunked.row_commitments, streamed.row_commitments);
        match (&chunked.coefficients, &streamed.coefficients) {
            (
                BlsDoryCoefficientStorage::AuthenticatedArtifact(left),
                BlsDoryCoefficientStorage::AuthenticatedArtifact(right),
            ) => {
                assert_eq!(left.spec(), right.spec());
                assert_eq!(left.digest(), right.digest());
            }
            _ => panic!("both commitment paths must retain authenticated artifacts"),
        }

        let points = vec![
            (0..variables)
                .map(|index| BlsDoryFr::from_u64(index as u64 + 2))
                .collect::<Vec<_>>(),
            (0..variables)
                .map(|index| BlsDoryFr::from_u64(index as u64 + 19))
                .collect::<Vec<_>>(),
        ];
        let chunked_refs = vec![&chunked, &chunked];
        let streamed_refs = vec![&streamed, &streamed];
        let chunked_proof = prove_bls_dory_opening_refs_with_scratch(
            b"chunked-writer-equivalence",
            test_layout(variables),
            &chunked_refs,
            &points,
            &setup,
            None,
        )
        .unwrap();
        let streamed_proof = prove_bls_dory_opening_refs_with_scratch(
            b"chunked-writer-equivalence",
            test_layout(variables),
            &streamed_refs,
            &points,
            &setup,
            None,
        )
        .unwrap();
        assert_eq!(chunked_proof, streamed_proof);
    }

    #[test]
    fn prepared_opening_no_longer_borrows_authenticated_sources() {
        let variables = 8;
        let nu = variables / 2;
        let sigma = variables - nu;
        let setup = deterministic_bls_dory_setup(variables).unwrap();
        let scratch = ScratchDirectory::create();
        let mut source = fixture_row_source(variables);
        let materialized =
            commit_bls_dory_polynomial(source.coefficients.clone(), nu, sigma, &setup).unwrap();
        let artifact =
            commit_bls_dory_row_source_with_scratch(&mut source, nu, sigma, &setup, &scratch.0)
                .unwrap();
        let artifact_path = artifact.coefficient_artifact_path().unwrap().to_path_buf();
        let points = vec![
            (0..variables)
                .map(|index| BlsDoryFr::from_u64(index as u64 + 23))
                .collect::<Vec<_>>(),
            (0..variables)
                .map(|index| BlsDoryFr::from_u64(index as u64 + 41))
                .collect::<Vec<_>>(),
        ];
        let ordinary = prove_bls_dory_same_commitment_openings(
            b"prepared-source-release",
            test_layout(variables),
            &materialized,
            &points,
            &setup,
        )
        .unwrap();
        let artifact_refs = vec![&artifact; points.len()];
        let prepared = prepare_bls_dory_opening_refs(
            b"prepared-source-release",
            test_layout(variables),
            &artifact_refs,
            &points,
            &setup,
            Some(&scratch.0),
        )
        .unwrap();
        drop(artifact_refs);
        drop(artifact);
        assert!(!artifact_path.exists());
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
        let released = finish_prepared_bls_dory_opening(prepared, &setup).unwrap();
        assert_eq!(released, ordinary);
    }

    #[test]
    #[ignore = "release-only scaling benchmark selected through CMFD_BLS_MODEL_WRITER_BENCH_VARIABLES"]
    fn authenticated_model_writer_scaling_benchmark() {
        let variables = std::env::var("CMFD_BLS_MODEL_WRITER_BENCH_VARIABLES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(19);
        assert!((8..=23).contains(&variables));
        let nu = variables / 2;
        let sigma = variables - nu;
        let explicit = 1usize << variables;
        let setup_start = std::time::Instant::now();
        let setup = deterministic_bls_dory_setup(variables).unwrap();
        let setup_millis = setup_start.elapsed().as_millis();
        let serial_scratch = ScratchDirectory::create();
        let serial_started = std::time::Instant::now();
        let serial = serial_model_writer_reference(&serial_scratch.0, explicit, nu, sigma, &setup);
        let serial_millis = serial_started.elapsed().as_millis();
        let parallel_scratch = ScratchDirectory::create();
        let mut writer = BlsDoryCommittedPolynomialWriter::create(
            &parallel_scratch.0,
            explicit,
            nu,
            sigma,
            &setup,
        )
        .unwrap();
        let window_bytes = writer.pending_capacity * std::mem::size_of::<BlsDoryFr>();
        let started = std::time::Instant::now();
        let scalar_chunk = 1usize << 16;
        for start in (0..explicit).step_by(scalar_chunk) {
            let end = start.saturating_add(scalar_chunk).min(explicit);
            let scalars = (start..end).map(benchmark_model_scalar).collect::<Vec<_>>();
            writer.write_scalars(&scalars).unwrap();
        }
        let parallel = writer.finish().unwrap();
        let parallel_millis = started.elapsed().as_millis();
        assert_eq!(parallel.commitment, serial.commitment);
        assert_eq!(parallel.row_commitments, serial.row_commitments);
        match (&parallel.coefficients, &serial.coefficients) {
            (
                BlsDoryCoefficientStorage::AuthenticatedArtifact(left),
                BlsDoryCoefficientStorage::AuthenticatedArtifact(right),
            ) => {
                assert_eq!(left.spec(), right.spec());
                assert_eq!(left.digest(), right.digest());
            }
            _ => panic!("both benchmark paths must retain authenticated artifacts"),
        }
        let artifact_bytes = std::fs::metadata(parallel.coefficient_artifact_path().unwrap())
            .unwrap()
            .len();
        println!(
            "CMFD_BLS_MODEL_WRITER_BENCHMARK {{\"variables\":{variables},\"coefficients\":{explicit},\"setup_millis\":{setup_millis},\"serial_millis\":{serial_millis},\"parallel_millis\":{parallel_millis},\"window_bytes\":{window_bytes},\"artifact_bytes\":{artifact_bytes}}}"
        );
    }

    #[test]
    fn implicit_zero_tail_preserves_proof_and_bounds_explicit_source_work() {
        let variables = 8;
        let nu = variables / 2;
        let sigma = variables - nu;
        let setup = deterministic_bls_dory_setup(variables).unwrap();
        let scratch = ScratchDirectory::create();
        let mut source = fixture_row_source(variables);
        source.explicit_coefficients = 64;
        let mut canonical_coefficients = source.coefficients.clone();
        canonical_coefficients[source.explicit_coefficients..].fill(BlsDoryFr::zero());
        let materialized =
            commit_bls_dory_polynomial(canonical_coefficients, nu, sigma, &setup).unwrap();
        let sparse =
            commit_bls_dory_row_source_with_scratch(&mut source, nu, sigma, &setup, &scratch.0)
                .unwrap();
        assert_eq!(source.reads, 4);
        assert_eq!(sparse.coefficient_count(), 1 << variables);
        assert_eq!(sparse.explicit_coefficient_count(), 64);
        assert_eq!(sparse.commitment, materialized.commitment);
        assert_eq!(sparse.row_commitments, materialized.row_commitments);
        let artifact_bytes = std::fs::metadata(sparse.coefficient_artifact_path().unwrap())
            .unwrap()
            .len();
        assert!(artifact_bytes < ((1u64 << variables) * 32));

        let points = vec![
            (0..variables)
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 5) * 13))
                .collect::<Vec<_>>(),
            (0..variables)
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 7) * 17))
                .collect::<Vec<_>>(),
        ];
        let ordinary = prove_bls_dory_same_commitment_openings(
            b"implicit-zero-tail",
            test_layout(variables),
            &materialized,
            &points,
            &setup,
        )
        .unwrap();
        let sparse_refs = vec![&sparse; points.len()];
        let sparse_proof = prove_bls_dory_opening_refs_with_scratch(
            b"implicit-zero-tail",
            test_layout(variables),
            &sparse_refs,
            &points,
            &setup,
            Some(&scratch.0),
        )
        .unwrap();
        assert_eq!(sparse_proof, ordinary);
        verify_bls_dory_openings(
            b"implicit-zero-tail",
            test_layout(variables),
            &sparse_proof.0,
            &sparse_proof.1,
            &setup,
        )
        .unwrap();
        drop(sparse);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn aggregate_layout_allows_the_setup_cap() {
        validate_layout(8, MAX_BLS_DORY_SETUP_VARIABLES - 8).unwrap();
        assert_eq!(
            validate_layout(8, MAX_BLS_DORY_SETUP_VARIABLES - 7),
            Err(BlsDoryAggregateError::InvalidDimension)
        );
    }

    #[test]
    fn exact_layout_rejects_same_total_partition_substitution() {
        let setup = deterministic_bls_dory_setup(8).unwrap();
        let expected_layout = BlsDoryAggregateLayout::new(3, 3).unwrap();
        let wrong_layout = BlsDoryAggregateLayout::new(2, 4).unwrap();
        let coefficients = (0..64)
            .map(|index| BlsDoryFr::from_u64(index + 1))
            .collect::<Vec<_>>();
        let expected = commit_bls_dory_polynomial(coefficients.clone(), 3, 3, &setup).unwrap();
        let wrong = commit_bls_dory_polynomial(coefficients, 2, 4, &setup).unwrap();
        let point = (0..6)
            .map(|index| BlsDoryFr::from_u64(index + 7))
            .collect::<Vec<_>>();

        assert!(expected.matches_layout(expected_layout, &setup));
        assert!(!wrong.matches_layout(expected_layout, &setup));
        assert!(matches!(
            BlsDoryDeferredOpeningSet::unopened(vec![expected.clone(), wrong.clone()]),
            Err(BlsDoryAggregateError::MixedStatement)
        ));
        assert!(matches!(
            BlsDoryDeferredOpeningSet::new(
                vec![expected, wrong.clone()],
                vec![0],
                vec![point.clone()],
            ),
            Err(BlsDoryAggregateError::MixedStatement)
        ));
        assert!(matches!(
            prove_bls_dory_openings(
                b"same-total-layout",
                expected_layout,
                std::slice::from_ref(&wrong),
                std::slice::from_ref(&point),
                &setup,
            ),
            Err(BlsDoryAggregateError::MixedStatement)
        ));

        let (claims, proof) = prove_bls_dory_openings(
            b"same-total-layout",
            wrong_layout,
            std::slice::from_ref(&wrong),
            std::slice::from_ref(&point),
            &setup,
        )
        .unwrap();
        verify_bls_dory_openings(b"same-total-layout", wrong_layout, &claims, &proof, &setup)
            .unwrap();
        assert_eq!(
            verify_bls_dory_openings(
                b"same-total-layout",
                expected_layout,
                &claims,
                &proof,
                &setup,
            ),
            Err(BlsDoryAggregateError::MixedStatement)
        );
    }

    #[test]
    #[ignore = "release-only integration above the dense Dory variable cap"]
    fn authenticated_scratch_accepts_above_the_dense_variable_cap() {
        let variables = MAX_BLS_DORY_PROTOTYPE_VARIABLES + 1;
        let nu = variables / 2;
        let sigma = variables - nu;
        let setup = deterministic_bls_dory_setup(variables).unwrap();
        let scratch = ScratchDirectory::create();
        let coefficients = (0..64)
            .map(|index| BlsDoryFr::from_u64(index + 1))
            .collect::<Vec<_>>();
        assert!(matches!(
            commit_bls_dory_padded_prefix_with_optional_scratch(
                &coefficients,
                nu,
                sigma,
                &setup,
                None,
            ),
            Err(BlsDoryAggregateError::InvalidDimension)
        ));
        let polynomial = commit_bls_dory_padded_prefix_with_optional_scratch(
            &coefficients,
            nu,
            sigma,
            &setup,
            Some(&scratch.0),
        )
        .unwrap();
        let point = (0..variables)
            .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 3) * 11))
            .collect::<Vec<_>>();
        let claim = BlsDoryOpeningClaim {
            commitment: polynomial.commitment(),
            evaluation: polynomial.evaluate(&point).unwrap(),
            point,
        };
        statement_transcript(b"above-dense-cap", &setup.identity(), &[claim], nu, sigma).unwrap();
        drop(polynomial);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn authenticated_row_source_fails_closed_and_cleans_partial_artifacts() {
        let variables = 6;
        let nu = variables / 2;
        let sigma = variables - nu;
        let setup = deterministic_bls_dory_setup(variables).unwrap();
        let scratch = ScratchDirectory::create();
        let mut failing = fixture_row_source(variables);
        failing.fail_at = Some(1);
        assert!(matches!(
            commit_bls_dory_row_source_with_scratch(&mut failing, nu, sigma, &setup, &scratch.0,),
            Err(BlsDoryAggregateError::CoefficientSource)
        ));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);

        let mut short = fixture_row_source(variables);
        short.short_at = Some(0);
        assert!(matches!(
            commit_bls_dory_row_source_with_scratch(&mut short, nu, sigma, &setup, &scratch.0,),
            Err(BlsDoryAggregateError::InvalidCoefficientCount)
        ));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);

        let mut source = fixture_row_source(variables);
        let committed =
            commit_bls_dory_row_source_with_scratch(&mut source, nu, sigma, &setup, &scratch.0)
                .unwrap();
        let path = committed.coefficient_artifact_path().unwrap();
        let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        file.seek(SeekFrom::Start(100)).unwrap();
        file.write_all(&[0xff]).unwrap();
        file.flush().unwrap();
        let point = vec![BlsDoryFr::from_u64(7); variables];
        assert_eq!(
            prove_bls_dory_openings(
                b"corrupt-row-source",
                test_layout(variables),
                std::slice::from_ref(&committed),
                &[point],
                &setup,
            ),
            Err(BlsDoryAggregateError::ProverStorage)
        );
        drop(file);
        drop(committed);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn statement_order_setup_and_proof_mutations_are_rejected() {
        let Fixture {
            setup,
            layout,
            polynomials,
            points,
        } = fixture(6, 3);
        let (claims, proof) =
            prove_bls_dory_openings(b"binding-a", layout, &polynomials, &points, &setup).unwrap();

        assert!(verify_bls_dory_openings(b"binding-b", layout, &claims, &proof, &setup).is_err());

        let mut changed = claims.clone();
        changed[0].evaluation = changed[0].evaluation + BlsDoryFr::one();
        assert!(verify_bls_dory_openings(b"binding-a", layout, &changed, &proof, &setup).is_err());

        let mut changed = claims.clone();
        changed[1].point[0] = changed[1].point[0] + BlsDoryFr::one();
        assert!(verify_bls_dory_openings(b"binding-a", layout, &changed, &proof, &setup).is_err());

        let mut changed = claims.clone();
        changed[2].commitment = changed[2].commitment.scale(&BlsDoryFr::from_u64(2));
        assert!(verify_bls_dory_openings(b"binding-a", layout, &changed, &proof, &setup).is_err());

        let mut reordered = claims.clone();
        reordered.swap(0, 1);
        assert!(
            verify_bls_dory_openings(b"binding-a", layout, &reordered, &proof, &setup).is_err()
        );

        let other_setup = deterministic_bls_dory_setup(8).unwrap();
        assert!(
            verify_bls_dory_openings(b"binding-a", layout, &claims, &proof, &other_setup).is_err()
        );

        let foreign = commit_bls_dory_polynomial(
            polynomials[0].materialized_coefficients().unwrap().to_vec(),
            3,
            3,
            &other_setup,
        )
        .unwrap();
        let mut mixed = polynomials.clone();
        mixed[0] = foreign;
        assert_eq!(
            prove_bls_dory_openings(b"binding-a", layout, &mixed, &points, &setup),
            Err(BlsDoryAggregateError::MixedStatement)
        );

        let mut changed_sumcheck = proof.clone();
        changed_sumcheck[WIRE_HEADER_BYTES] ^= 1;
        assert!(
            verify_bls_dory_openings(b"binding-a", layout, &claims, &changed_sumcheck, &setup,)
                .is_err()
        );

        let mut changed_dory = proof.clone();
        let dory_offset = WIRE_HEADER_BYTES + 6 * 3 * scalar_bytes();
        changed_dory[dory_offset] ^= 1;
        assert!(
            verify_bls_dory_openings(b"binding-a", layout, &claims, &changed_dory, &setup).is_err()
        );
    }

    #[test]
    fn parser_preflights_shape_and_rejects_trailing_bytes() {
        let Fixture {
            setup,
            layout,
            polynomials,
            points,
        } = fixture(6, 2);
        let (claims, proof) =
            prove_bls_dory_openings(b"parser", layout, &polynomials, &points, &setup).unwrap();
        let dory_offset = WIRE_HEADER_BYTES + 6 * 3 * scalar_bytes();
        let vmv = 2 * gt_bytes() + g1_bytes();

        let mut changed_round_count = proof.clone();
        changed_round_count[dory_offset + vmv..dory_offset + vmv + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            verify_bls_dory_openings(b"parser", layout, &claims, &changed_round_count, &setup,),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );

        let mut trailing = proof.clone();
        trailing.push(0);
        assert_eq!(
            verify_bls_dory_openings(b"parser", layout, &claims, &trailing, &setup),
            Err(BlsDoryAggregateError::InvalidProofShape)
        );
    }

    #[test]
    fn production_gate_stays_closed_with_only_real_blockers() {
        assert_eq!(
            require_bls_dory_aggregate_production_ready(),
            Err(BlsDoryAggregateError::NotProductionReady)
        );
        assert_eq!(BLS_DORY_AGGREGATE_PRODUCTION_BLOCKERS.len(), 3);
        let projected = projected_bls_dory_aggregate_bytes(31).unwrap();
        assert_eq!(projected, 66_559);
        assert!(projected < MAX_BLS_DORY_AGGREGATE_BYTES);
    }
}
