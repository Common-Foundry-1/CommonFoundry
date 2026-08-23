//! Deterministic BLS12-381 backend checkpoint for Dory.
//!
//! The upstream `dory-pcs` crate currently exposes only a BN254 adapter. This
//! module supplies the minimum BLS12-381 field, group, pairing, polynomial, and
//! transcript adapters needed to exercise the generic protocol. Setup points
//! are derived independently with domain-separated IETF hash-to-curve rather
//! than sampled from an operating-system RNG.
//!
//! This remains a non-consensus prototype: its arithmetic routines are simple
//! CPU-parallel references, the complete ForgeMatrix AIR is not connected, and
//! its codec has not been externally audited.

use std::io::{Read, Write};
use std::ops::{Add, Mul, Neg, Sub};

use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective, g1, g2};
use ark_ec::{
    AffineRepr,
    hashing::{HashToCurve, curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher},
    pairing::{MillerLoopOutput, Pairing, PairingOutput},
};
use ark_ff::{
    BigInteger, Field as ArkField, PrimeField, UniformRand, Zero, field_hashers::DefaultFieldHasher,
};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress as ArkCompress, Valid as ArkValid,
    Validate as ArkValidate,
};
use dory_pcs::mode::Mode;
use dory_pcs::primitives::{
    DoryDeserialize, DorySerialize,
    arithmetic::{DoryRoutines, Field, Group, PairingCurve},
    poly::{MultilinearLagrange, Polynomial},
    serialization::{Compress, SerializationError, Valid, Validate},
    transcript::Transcript,
};
#[cfg(test)]
use dory_pcs::proof::DoryProof;
use dory_pcs::setup::{ProverSetup, VerifierSetup};
#[cfg(test)]
use dory_pcs::{Transparent, prove, verify};
use rayon::prelude::*;
use sha2::Sha256;
use thiserror::Error;

/// Version of the deterministic BLS12-381 setup derivation.
pub const BLS_DORY_SETUP_VERSION: u16 = 1;
/// Version of the BLS12-381 Fiat-Shamir transcript and challenge sampler.
pub const BLS_DORY_TRANSCRIPT_VERSION: u16 = 2;
/// Transcript v2 samples exactly uniformly from the nonzero scalar field.
pub const BLS_DORY_EXACT_NONZERO_CHALLENGE_SAMPLING: bool = true;
/// This backend is a research checkpoint and cannot activate consensus.
pub const BLS_DORY_PROTOTYPE_PRODUCTION_READY: bool = false;
/// Largest fully materialized polynomial accepted by the reference prover.
pub const MAX_BLS_DORY_PROTOTYPE_VARIABLES: usize = 16;
/// Largest deterministic setup needed by the shared production layout.
///
/// The setup contains only square-root-sized generator vectors. Polynomial
/// materialization remains independently capped by
/// [`MAX_BLS_DORY_PROTOTYPE_VARIABLES`].
pub const MAX_BLS_DORY_SETUP_VARIABLES: usize = 33;

const G1_DOMAIN: &[u8] = b"CMFD_DORY_BLS12381G1_XMD:SHA-256_SSWU_RO_V1";
const G2_DOMAIN: &[u8] = b"CMFD_DORY_BLS12381G2_XMD:SHA-256_SSWU_RO_V1";
const SETUP_IDENTITY_DOMAIN: &str = "CMFD/FORGEMATRIX/DORY-BLS12-381-SETUP/V1";
const TRANSCRIPT_DOMAIN: &str = "CMFD/FORGEMATRIX/DORY-BLS12-381-OPENING/V2";

type G1Hasher =
    MapToCurveBasedHasher<G1Projective, DefaultFieldHasher<Sha256, 128>, WBMap<g1::Config>>;
type G2Hasher =
    MapToCurveBasedHasher<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<g2::Config>>;

/// BLS12-381 scalar field wrapper implementing Dory's arithmetic traits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BlsDoryFr(pub Fr);

/// BLS12-381 G1 wrapper implementing Dory's arithmetic traits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BlsDoryG1(pub G1Projective);

/// BLS12-381 G2 wrapper implementing Dory's arithmetic traits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BlsDoryG2(pub G2Projective);

/// BLS12-381 target-group wrapper implementing Dory's arithmetic traits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BlsDoryGt(pub PairingOutput<Bls12_381>);

macro_rules! impl_dory_serialization {
    ($wrapper:ty) => {
        impl Valid for $wrapper {
            fn check(&self) -> Result<(), SerializationError> {
                ArkValid::check(&self.0)
                    .map_err(|error| SerializationError::InvalidData(error.to_string()))
            }
        }

        impl DorySerialize for $wrapper {
            fn serialize_with_mode<W: Write>(
                &self,
                writer: W,
                compress: Compress,
            ) -> Result<(), SerializationError> {
                let compress = match compress {
                    Compress::Yes => ArkCompress::Yes,
                    Compress::No => ArkCompress::No,
                };
                CanonicalSerialize::serialize_with_mode(&self.0, writer, compress)
                    .map_err(|error| SerializationError::InvalidData(error.to_string()))
            }

            fn serialized_size(&self, compress: Compress) -> usize {
                let compress = match compress {
                    Compress::Yes => ArkCompress::Yes,
                    Compress::No => ArkCompress::No,
                };
                CanonicalSerialize::serialized_size(&self.0, compress)
            }
        }

        impl DoryDeserialize for $wrapper {
            fn deserialize_with_mode<R: Read>(
                reader: R,
                compress: Compress,
                validate: Validate,
            ) -> Result<Self, SerializationError> {
                let compress = match compress {
                    Compress::Yes => ArkCompress::Yes,
                    Compress::No => ArkCompress::No,
                };
                let validate = match validate {
                    Validate::Yes => ArkValidate::Yes,
                    Validate::No => ArkValidate::No,
                };
                CanonicalDeserialize::deserialize_with_mode(reader, compress, validate)
                    .map(Self)
                    .map_err(|error| SerializationError::InvalidData(error.to_string()))
            }
        }
    };
}

impl_dory_serialization!(BlsDoryFr);
impl_dory_serialization!(BlsDoryG1);
impl_dory_serialization!(BlsDoryG2);
impl_dory_serialization!(BlsDoryGt);

impl Add for BlsDoryFr {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Add<&Self> for BlsDoryFr {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        self + *rhs
    }
}

impl Sub for BlsDoryFr {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Sub<&Self> for BlsDoryFr {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        self - *rhs
    }
}

impl Mul for BlsDoryFr {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl Mul<&Self> for BlsDoryFr {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        self * *rhs
    }
}

impl Neg for BlsDoryFr {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl Field for BlsDoryFr {
    fn zero() -> Self {
        Self(Fr::from(0u64))
    }

    fn one() -> Self {
        Self(Fr::from(1u64))
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    fn add(&self, rhs: &Self) -> Self {
        *self + *rhs
    }

    fn sub(&self, rhs: &Self) -> Self {
        *self - *rhs
    }

    fn mul(&self, rhs: &Self) -> Self {
        *self * *rhs
    }

    fn inv(self) -> Option<Self> {
        self.0.inverse().map(Self)
    }

    fn random() -> Self {
        Self(Fr::rand(&mut rand_core::OsRng))
    }

    fn from_u64(val: u64) -> Self {
        Self(Fr::from(val))
    }

    fn from_i64(val: i64) -> Self {
        if val >= 0 {
            Self::from_u64(val as u64)
        } else {
            -Self::from_u64(val.unsigned_abs())
        }
    }
}

macro_rules! impl_group_ops {
    ($group:ty, $scalar:ty) => {
        impl Add for $group {
            type Output = Self;

            fn add(self, rhs: Self) -> Self::Output {
                Self(self.0 + rhs.0)
            }
        }

        impl Add<&Self> for $group {
            type Output = Self;

            fn add(self, rhs: &Self) -> Self::Output {
                self + *rhs
            }
        }

        impl Sub for $group {
            type Output = Self;

            fn sub(self, rhs: Self) -> Self::Output {
                Self(self.0 - rhs.0)
            }
        }

        impl Sub<&Self> for $group {
            type Output = Self;

            fn sub(self, rhs: &Self) -> Self::Output {
                self - *rhs
            }
        }

        impl Neg for $group {
            type Output = Self;

            fn neg(self) -> Self::Output {
                Self(-self.0)
            }
        }

        impl Mul<$group> for $scalar {
            type Output = $group;

            fn mul(self, rhs: $group) -> Self::Output {
                rhs.scale(&self)
            }
        }

        impl Mul<&$group> for $scalar {
            type Output = $group;

            fn mul(self, rhs: &$group) -> Self::Output {
                rhs.scale(&self)
            }
        }
    };
}

impl_group_ops!(BlsDoryG1, BlsDoryFr);
impl_group_ops!(BlsDoryG2, BlsDoryFr);
impl_group_ops!(BlsDoryGt, BlsDoryFr);

impl Group for BlsDoryG1 {
    type Scalar = BlsDoryFr;

    fn identity() -> Self {
        Self(G1Projective::zero())
    }

    fn add(&self, rhs: &Self) -> Self {
        *self + *rhs
    }

    fn neg(&self) -> Self {
        -*self
    }

    fn scale(&self, scalar: &Self::Scalar) -> Self {
        Self(self.0 * scalar.0)
    }

    fn random() -> Self {
        Self(G1Projective::rand(&mut rand_core::OsRng))
    }
}

impl Group for BlsDoryG2 {
    type Scalar = BlsDoryFr;

    fn identity() -> Self {
        Self(G2Projective::zero())
    }

    fn add(&self, rhs: &Self) -> Self {
        *self + *rhs
    }

    fn neg(&self) -> Self {
        -*self
    }

    fn scale(&self, scalar: &Self::Scalar) -> Self {
        Self(self.0 * scalar.0)
    }

    fn random() -> Self {
        Self(G2Projective::rand(&mut rand_core::OsRng))
    }
}

impl Group for BlsDoryGt {
    type Scalar = BlsDoryFr;

    fn identity() -> Self {
        Self(PairingOutput::zero())
    }

    fn add(&self, rhs: &Self) -> Self {
        *self + *rhs
    }

    fn neg(&self) -> Self {
        -*self
    }

    fn scale(&self, scalar: &Self::Scalar) -> Self {
        Self(PairingOutput(self.0.0.pow(scalar.0.into_bigint())))
    }

    fn random() -> Self {
        Self(Bls12_381::pairing(
            G1Projective::rand(&mut rand_core::OsRng),
            G2Projective::rand(&mut rand_core::OsRng),
        ))
    }
}

/// Dory pairing marker for the BLS12-381 adapters.
#[derive(Clone, Debug, Default)]
pub struct BlsDoryCurve;

const MIN_PARALLEL_PAIRINGS: usize = 32;
const MAX_PAIRING_CHUNK_SIZE: usize = 128;

fn pairing_chunk_size(total: usize) -> usize {
    debug_assert!(total >= MIN_PARALLEL_PAIRINGS);
    total
        .div_ceil(rayon::current_num_threads())
        .clamp(MIN_PARALLEL_PAIRINGS, MAX_PAIRING_CHUNK_SIZE)
}

fn bls_miller_loop(points: &[BlsDoryG1], twists: &[BlsDoryG2]) -> MillerLoopOutput<Bls12_381> {
    let prepared_points = points
        .iter()
        .map(|point| <Bls12_381 as Pairing>::G1Prepared::from(&point.0))
        .collect::<Vec<_>>();
    let prepared_twists = twists
        .iter()
        .map(|twist| <Bls12_381 as Pairing>::G2Prepared::from(&twist.0))
        .collect::<Vec<_>>();
    Bls12_381::multi_miller_loop(prepared_points, prepared_twists)
}

fn finish_bls_multi_pairing(miller_output: MillerLoopOutput<Bls12_381>) -> BlsDoryGt {
    BlsDoryGt(
        Bls12_381::final_exponentiation(miller_output)
            .expect("a Miller loop over valid BLS12-381 group points is nonzero"),
    )
}

impl PairingCurve for BlsDoryCurve {
    type G1 = BlsDoryG1;
    type G2 = BlsDoryG2;
    type GT = BlsDoryGt;

    fn pair(point: &Self::G1, twist: &Self::G2) -> Self::GT {
        BlsDoryGt(Bls12_381::pairing(point.0, twist.0))
    }

    fn multi_pair(points: &[Self::G1], twists: &[Self::G2]) -> Self::GT {
        assert_eq!(
            points.len(),
            twists.len(),
            "multi_pair requires equal length vectors"
        );
        if points.is_empty() {
            return Self::GT::identity();
        }

        let miller_output = if points.len() < MIN_PARALLEL_PAIRINGS {
            bls_miller_loop(points, twists)
        } else {
            let chunk_size = pairing_chunk_size(points.len());
            points
                .par_chunks(chunk_size)
                .zip(twists.par_chunks(chunk_size))
                .map(|(point_chunk, twist_chunk)| bls_miller_loop(point_chunk, twist_chunk))
                .reduce_with(|left, right| MillerLoopOutput(left.0 * right.0))
                .expect("nonempty inputs produce at least one Miller-loop chunk")
        };
        finish_bls_multi_pairing(miller_output)
    }
}

/// Parallel reference routines for BLS12-381 G1.
pub struct BlsDoryG1Routines;
/// Parallel reference routines for BLS12-381 G2.
pub struct BlsDoryG2Routines;

macro_rules! impl_reference_routines {
    ($routines:ty, $group:ty) => {
        impl DoryRoutines<$group> for $routines {
            fn msm(bases: &[$group], scalars: &[BlsDoryFr]) -> $group {
                assert_eq!(bases.len(), scalars.len());
                bases
                    .par_iter()
                    .zip(scalars.par_iter())
                    .map(|(base, scalar)| base.scale(scalar))
                    .reduce(<$group>::identity, |sum, value| sum + value)
            }

            fn fixed_base_vector_scalar_mul(base: &$group, scalars: &[BlsDoryFr]) -> Vec<$group> {
                scalars
                    .par_iter()
                    .map(|scalar| base.scale(scalar))
                    .collect()
            }

            fn fixed_scalar_mul_bases_then_add(
                bases: &[$group],
                values: &mut [$group],
                scalar: &BlsDoryFr,
            ) {
                assert_eq!(bases.len(), values.len());
                values
                    .par_iter_mut()
                    .zip(bases.par_iter())
                    .for_each(|(value, base)| *value = *value + base.scale(scalar));
            }

            fn fixed_scalar_mul_vs_then_add(
                values: &mut [$group],
                addends: &[$group],
                scalar: &BlsDoryFr,
            ) {
                assert_eq!(values.len(), addends.len());
                values
                    .par_iter_mut()
                    .zip(addends.par_iter())
                    .for_each(|(value, addend)| *value = value.scale(scalar) + *addend);
            }
        }
    };
}

impl_reference_routines!(BlsDoryG1Routines, BlsDoryG1);
impl_reference_routines!(BlsDoryG2Routines, BlsDoryG2);

/// Evaluation-form multilinear polynomial over the BLS12-381 scalar field.
#[derive(Clone, Debug)]
pub struct BlsDoryPolynomial {
    coefficients: Vec<BlsDoryFr>,
    variables: usize,
}

impl BlsDoryPolynomial {
    pub fn new(coefficients: Vec<BlsDoryFr>) -> Result<Self, BlsDoryPrototypeError> {
        if coefficients.is_empty() || !coefficients.len().is_power_of_two() {
            return Err(BlsDoryPrototypeError::InvalidSize);
        }
        let variables = coefficients.len().ilog2() as usize;
        if variables > MAX_BLS_DORY_PROTOTYPE_VARIABLES {
            return Err(BlsDoryPrototypeError::InvalidSize);
        }
        Ok(Self {
            coefficients,
            variables,
        })
    }

    pub(crate) fn coefficients(&self) -> &[BlsDoryFr] {
        &self.coefficients
    }
}

impl Polynomial<BlsDoryFr> for BlsDoryPolynomial {
    fn num_vars(&self) -> usize {
        self.variables
    }

    fn evaluate(&self, point: &[BlsDoryFr]) -> BlsDoryFr {
        assert_eq!(point.len(), self.variables);
        let basis = lagrange_basis(point);
        self.coefficients
            .iter()
            .zip(basis)
            .fold(BlsDoryFr::zero(), |sum, (coefficient, weight)| {
                sum + *coefficient * weight
            })
    }

    fn commit<E, Mo, M1>(
        &self,
        nu: usize,
        sigma: usize,
        setup: &ProverSetup<E>,
    ) -> Result<(E::GT, Vec<E::G1>, BlsDoryFr), dory_pcs::error::DoryError>
    where
        E: PairingCurve,
        Mo: Mode,
        M1: DoryRoutines<E::G1>,
        E::G1: Group<Scalar = BlsDoryFr>,
        E::GT: Group<Scalar = BlsDoryFr>,
    {
        let expected = 1usize << (nu + sigma);
        if self.coefficients.len() != expected {
            return Err(dory_pcs::error::DoryError::InvalidSize {
                expected,
                actual: self.coefficients.len(),
            });
        }
        let rows = 1usize << nu;
        let columns = 1usize << sigma;
        let row_commitments = (0..rows)
            .map(|row| {
                M1::msm(
                    &setup.g1_vec[..columns],
                    &self.coefficients[row * columns..(row + 1) * columns],
                )
            })
            .collect::<Vec<_>>();
        let tier_two = E::multi_pair_g2_setup(&row_commitments, &setup.g2_vec[..rows]);
        let blind = Mo::sample();
        Ok((
            Mo::mask(tier_two, &setup.ht, &blind),
            row_commitments,
            blind,
        ))
    }
}

impl MultilinearLagrange<BlsDoryFr> for BlsDoryPolynomial {
    fn vector_matrix_product(&self, left: &[BlsDoryFr], nu: usize, sigma: usize) -> Vec<BlsDoryFr> {
        let rows = 1usize << nu;
        let columns = 1usize << sigma;
        (0..columns)
            .map(|column| {
                (0..rows).fold(BlsDoryFr::zero(), |sum, row| {
                    sum + left[row] * self.coefficients[row * columns + column]
                })
            })
            .collect()
    }
}

fn lagrange_basis(point: &[BlsDoryFr]) -> Vec<BlsDoryFr> {
    let mut basis = vec![BlsDoryFr::one(); 1usize << point.len()];
    let mut active = 1usize;
    for coordinate in point {
        for index in (0..active).rev() {
            let value = basis[index];
            basis[index] = value * (BlsDoryFr::one() - *coordinate);
            basis[index + active] = value * coordinate;
        }
        active *= 2;
    }
    basis
}

/// BLAKE3 Fiat-Shamir transcript specialized to the BLS12-381 Dory curve.
#[derive(Clone)]
pub struct BlsDoryTranscript {
    hasher: blake3::Hasher,
}

impl BlsDoryTranscript {
    pub fn new(domain: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(TRANSCRIPT_DOMAIN);
        absorb_bytes(
            &mut hasher,
            b"transcript-version",
            &BLS_DORY_TRANSCRIPT_VERSION.to_le_bytes(),
        );
        absorb_bytes(&mut hasher, b"domain", domain);
        Self { hasher }
    }

    /// Current transcript digest for binding a following protocol phase.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        *self.hasher.finalize().as_bytes()
    }
}

impl Transcript for BlsDoryTranscript {
    type Curve = BlsDoryCurve;

    fn append_bytes(&mut self, label: &[u8], bytes: &[u8]) {
        absorb_bytes(&mut self.hasher, label, bytes);
    }

    fn append_field(&mut self, label: &[u8], value: &BlsDoryFr) {
        self.append_serde(label, value);
    }

    fn append_group<G: Group>(&mut self, label: &[u8], group: &G) {
        self.append_serde(label, group);
    }

    fn append_serde<S: DorySerialize>(&mut self, label: &[u8], value: &S) {
        let mut bytes = Vec::with_capacity(value.compressed_size());
        value
            .serialize_compressed(&mut bytes)
            .expect("serializing an in-memory transcript value cannot fail");
        self.append_bytes(label, &bytes);
    }

    fn challenge_scalar(&mut self, label: &[u8]) -> BlsDoryFr {
        absorb_bytes(&mut self.hasher, b"challenge-label", label);
        for counter in 0u32.. {
            let mut challenge_hasher = self.hasher.clone();
            challenge_hasher.update(&counter.to_le_bytes());
            let mut candidate = [0u8; 32];
            challenge_hasher.finalize_xof().fill(&mut candidate);
            if let Some(challenge) = canonical_nonzero_scalar(candidate) {
                absorb_bytes(&mut self.hasher, b"challenge-output", &candidate);
                return challenge;
            }
        }
        unreachable!("a nonzero scalar exists in the BLS12-381 field")
    }

    fn reset(&mut self, domain_label: &[u8]) {
        *self = Self::new(domain_label);
    }
}

fn canonical_nonzero_scalar(candidate: [u8; 32]) -> Option<BlsDoryFr> {
    let scalar = Fr::from_le_bytes_mod_order(&candidate);
    if scalar.is_zero() {
        return None;
    }
    let mut canonical = scalar.into_bigint().to_bytes_le();
    canonical.resize(candidate.len(), 0);
    (canonical.as_slice() == candidate).then_some(BlsDoryFr(scalar))
}

fn absorb_bytes(hasher: &mut blake3::Hasher, label: &[u8], bytes: &[u8]) {
    hasher.update(&(label.len() as u64).to_le_bytes());
    hasher.update(label);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Deterministically generated prover/verifier setup and its consensus-facing identity.
#[derive(Clone)]
pub struct DeterministicBlsDorySetup {
    prover: ProverSetup<BlsDoryCurve>,
    verifier: VerifierSetup<BlsDoryCurve>,
    identity: [u8; 32],
    max_log_n: usize,
}

impl DeterministicBlsDorySetup {
    /// Pinned identity of every generator and setup parameter.
    #[must_use]
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }

    /// Largest multilinear table dimension admitted by this setup.
    #[must_use]
    pub fn max_log_n(&self) -> usize {
        self.max_log_n
    }

    pub(crate) fn prover(&self) -> &ProverSetup<BlsDoryCurve> {
        &self.prover
    }

    pub(crate) fn verifier(&self) -> &VerifierSetup<BlsDoryCurve> {
        &self.verifier
    }

    pub(crate) fn commit_row_segment(
        &self,
        column_offset: usize,
        scalars: &[BlsDoryFr],
    ) -> Result<BlsDoryG1, BlsDoryPrototypeError> {
        let end = column_offset
            .checked_add(scalars.len())
            .ok_or(BlsDoryPrototypeError::InvalidSize)?;
        let generators = self
            .prover
            .g1_vec
            .get(column_offset..end)
            .ok_or(BlsDoryPrototypeError::InvalidSize)?;
        Ok(BlsDoryG1Routines::msm(generators, scalars))
    }

    pub(crate) fn pair_committed_row(
        &self,
        row_index: usize,
        commitment: &BlsDoryG1,
    ) -> Result<BlsDoryGt, BlsDoryPrototypeError> {
        let generator = self
            .prover
            .g2_vec
            .get(row_index)
            .ok_or(BlsDoryPrototypeError::InvalidSize)?;
        Ok(BlsDoryCurve::pair(commitment, generator))
    }

    /// Recompute every derived setup invariant before the setup is trusted.
    pub fn validate(&self) -> Result<(), BlsDoryPrototypeError> {
        if self.max_log_n == 0 || self.max_log_n > MAX_BLS_DORY_SETUP_VARIABLES {
            return Err(BlsDoryPrototypeError::InvalidSetup);
        }
        let generator_count = 1usize << self.max_log_n.div_ceil(2);
        if self.prover.g1_vec.len() != generator_count
            || self.prover.g2_vec.len() != generator_count
            || self.prover.ht != BlsDoryCurve::pair(&self.prover.h1, &self.prover.h2)
            || setup_identity(&self.prover, self.max_log_n)? != self.identity
        {
            return Err(BlsDoryPrototypeError::InvalidSetup);
        }

        let expected_verifier = self.prover.to_verifier_setup();
        let mut expected_bytes = Vec::new();
        let mut actual_bytes = Vec::new();
        expected_verifier
            .serialize_compressed(&mut expected_bytes)
            .map_err(|error| BlsDoryPrototypeError::Serialization(error.to_string()))?;
        self.verifier
            .serialize_compressed(&mut actual_bytes)
            .map_err(|error| BlsDoryPrototypeError::Serialization(error.to_string()))?;
        if expected_bytes != actual_bytes {
            return Err(BlsDoryPrototypeError::InvalidSetup);
        }
        Ok(())
    }
}

/// Errors from the BLS12-381 Dory backend checkpoint.
#[derive(Debug, Error)]
pub enum BlsDoryPrototypeError {
    #[error("BLS12-381 Dory prototype size is invalid")]
    InvalidSize,
    #[error("deterministic BLS12-381 setup is internally inconsistent")]
    InvalidSetup,
    #[error("hash-to-curve setup derivation failed: {0}")]
    HashToCurve(String),
    #[error("canonical serialization failed: {0}")]
    Serialization(String),
    #[error("Dory proof operation failed: {0}")]
    Dory(String),
}

/// Derive every generator from its role and index with IETF hash-to-curve.
pub fn deterministic_bls_dory_setup(
    max_log_n: usize,
) -> Result<DeterministicBlsDorySetup, BlsDoryPrototypeError> {
    if max_log_n == 0 || max_log_n > MAX_BLS_DORY_SETUP_VARIABLES {
        return Err(BlsDoryPrototypeError::InvalidSize);
    }
    let generator_count = 1usize << max_log_n.div_ceil(2);
    let g1_hasher = G1Hasher::new(G1_DOMAIN)
        .map_err(|error| BlsDoryPrototypeError::HashToCurve(error.to_string()))?;
    let g2_hasher = G2Hasher::new(G2_DOMAIN)
        .map_err(|error| BlsDoryPrototypeError::HashToCurve(error.to_string()))?;

    let g1_vec = (0..generator_count)
        .into_par_iter()
        .map(|index| hash_g1(&g1_hasher, b"column-generator", index as u64))
        .collect::<Result<Vec<_>, _>>()?;
    let g2_vec = (0..generator_count)
        .into_par_iter()
        .map(|index| hash_g2(&g2_hasher, b"row-generator", index as u64))
        .collect::<Result<Vec<_>, _>>()?;
    let h1 = hash_g1(&g1_hasher, b"blinding-generator", 0)?;
    let h2 = hash_g2(&g2_hasher, b"blinding-generator", 0)?;
    let ht = BlsDoryCurve::pair(&h1, &h2);
    let prover = ProverSetup {
        g1_vec,
        g2_vec,
        h1,
        h2,
        ht,
    };
    let identity = setup_identity(&prover, max_log_n)?;
    let verifier = prover.to_verifier_setup();
    Ok(DeterministicBlsDorySetup {
        prover,
        verifier,
        identity,
        max_log_n,
    })
}

fn hash_g1(hasher: &G1Hasher, role: &[u8], index: u64) -> Result<BlsDoryG1, BlsDoryPrototypeError> {
    let message = generator_message(role, index);
    hasher
        .hash(&message)
        .map(|point| BlsDoryG1(point.into_group()))
        .map_err(|error| BlsDoryPrototypeError::HashToCurve(error.to_string()))
}

fn hash_g2(hasher: &G2Hasher, role: &[u8], index: u64) -> Result<BlsDoryG2, BlsDoryPrototypeError> {
    let message = generator_message(role, index);
    hasher
        .hash(&message)
        .map(|point| BlsDoryG2(point.into_group()))
        .map_err(|error| BlsDoryPrototypeError::HashToCurve(error.to_string()))
}

fn generator_message(role: &[u8], index: u64) -> Vec<u8> {
    let mut message = Vec::with_capacity(2 + 8 + role.len());
    message.extend_from_slice(&BLS_DORY_SETUP_VERSION.to_le_bytes());
    message.extend_from_slice(&(role.len() as u64).to_le_bytes());
    message.extend_from_slice(role);
    message.extend_from_slice(&index.to_le_bytes());
    message
}

fn setup_identity(
    setup: &ProverSetup<BlsDoryCurve>,
    max_log_n: usize,
) -> Result<[u8; 32], BlsDoryPrototypeError> {
    let mut hasher = blake3::Hasher::new_derive_key(SETUP_IDENTITY_DOMAIN);
    hasher.update(&BLS_DORY_SETUP_VERSION.to_le_bytes());
    hasher.update(&(max_log_n as u64).to_le_bytes());
    absorb_groups(&mut hasher, b"g1", &setup.g1_vec)?;
    absorb_groups(&mut hasher, b"g2", &setup.g2_vec)?;
    absorb_group(&mut hasher, b"h1", &setup.h1)?;
    absorb_group(&mut hasher, b"h2", &setup.h2)?;
    absorb_group(&mut hasher, b"ht", &setup.ht)?;
    Ok(*hasher.finalize().as_bytes())
}

fn absorb_groups<G: Group + Sync>(
    hasher: &mut blake3::Hasher,
    label: &[u8],
    groups: &[G],
) -> Result<(), BlsDoryPrototypeError> {
    absorb_bytes(hasher, b"group-vector-label", label);
    absorb_bytes(
        hasher,
        b"group-vector-length",
        &(groups.len() as u64).to_le_bytes(),
    );
    let Some(first) = groups.first() else {
        return Ok(());
    };
    let element_bytes = first.compressed_size();
    let total_bytes = groups
        .len()
        .checked_mul(element_bytes)
        .ok_or(BlsDoryPrototypeError::InvalidSize)?;
    if element_bytes == 0 {
        return Err(BlsDoryPrototypeError::InvalidSize);
    }
    let mut encoded = vec![0_u8; total_bytes];
    groups
        .par_iter()
        .zip(encoded.par_chunks_exact_mut(element_bytes))
        .try_for_each(|(group, output)| {
            let mut writer = std::io::Cursor::new(output);
            group
                .serialize_compressed(&mut writer)
                .map_err(|error| BlsDoryPrototypeError::Serialization(error.to_string()))?;
            if writer.position() != element_bytes as u64 {
                return Err(BlsDoryPrototypeError::Serialization(
                    "group encoding has an unexpected length".to_owned(),
                ));
            }
            Ok(())
        })?;
    for group in encoded.chunks_exact(element_bytes) {
        absorb_bytes(hasher, b"group-vector-element", group);
    }
    Ok(())
}

fn absorb_group<G: Group>(
    hasher: &mut blake3::Hasher,
    label: &[u8],
    group: &G,
) -> Result<(), BlsDoryPrototypeError> {
    let mut encoded = Vec::with_capacity(group.compressed_size());
    group
        .serialize_compressed(&mut encoded)
        .map_err(|error| BlsDoryPrototypeError::Serialization(error.to_string()))?;
    absorb_bytes(hasher, label, &encoded);
    Ok(())
}

#[cfg(test)]
fn opening_transcript(
    setup_identity: &[u8; 32],
    commitment: &BlsDoryGt,
    point: &[BlsDoryFr],
    evaluation: &BlsDoryFr,
) -> BlsDoryTranscript {
    let mut transcript = BlsDoryTranscript::new(b"opening");
    transcript.append_bytes(b"setup-identity", setup_identity);
    transcript.append_group(b"commitment", commitment);
    transcript.append_bytes(b"point-length", &(point.len() as u64).to_le_bytes());
    for coordinate in point {
        transcript.append_field(b"point-coordinate", coordinate);
    }
    transcript.append_field(b"evaluation", evaluation);
    transcript
}

#[cfg(test)]
fn encode_transparent_proof(
    proof: &DoryProof<BlsDoryG1, BlsDoryG2, BlsDoryGt>,
) -> Result<Vec<u8>, BlsDoryPrototypeError> {
    if proof.first_messages.len() != proof.second_messages.len()
        || proof.first_messages.len() != proof.nu.max(proof.sigma)
        || proof.final_message.is_none()
    {
        return Err(BlsDoryPrototypeError::InvalidSize);
    }
    let mut encoded = Vec::new();
    append_serialized(&mut encoded, &proof.vmv_message.c)?;
    append_serialized(&mut encoded, &proof.vmv_message.d2)?;
    append_serialized(&mut encoded, &proof.vmv_message.e1)?;
    encoded.extend_from_slice(&(proof.first_messages.len() as u32).to_le_bytes());
    for message in &proof.first_messages {
        append_serialized(&mut encoded, &message.d1_left)?;
        append_serialized(&mut encoded, &message.d1_right)?;
        append_serialized(&mut encoded, &message.d2_left)?;
        append_serialized(&mut encoded, &message.d2_right)?;
        append_serialized(&mut encoded, &message.e1_beta)?;
        append_serialized(&mut encoded, &message.e2_beta)?;
    }
    for message in &proof.second_messages {
        append_serialized(&mut encoded, &message.c_plus)?;
        append_serialized(&mut encoded, &message.c_minus)?;
        append_serialized(&mut encoded, &message.e1_plus)?;
        append_serialized(&mut encoded, &message.e1_minus)?;
        append_serialized(&mut encoded, &message.e2_plus)?;
        append_serialized(&mut encoded, &message.e2_minus)?;
    }
    encoded.push(1);
    let final_message = proof
        .final_message
        .as_ref()
        .ok_or(BlsDoryPrototypeError::InvalidSize)?;
    append_serialized(&mut encoded, &final_message.e1)?;
    append_serialized(&mut encoded, &final_message.e2)?;
    encoded.extend_from_slice(&(proof.nu as u32).to_le_bytes());
    encoded.extend_from_slice(&(proof.sigma as u32).to_le_bytes());
    Ok(encoded)
}

#[cfg(test)]
fn append_serialized<T: DorySerialize>(
    output: &mut Vec<u8>,
    value: &T,
) -> Result<(), BlsDoryPrototypeError> {
    value
        .serialize_compressed(output)
        .map_err(|error| BlsDoryPrototypeError::Serialization(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deterministic_pairing_inputs(len: usize) -> (Vec<BlsDoryG1>, Vec<BlsDoryG2>) {
        let g1 = ark_bls12_381::G1Affine::generator().into_group();
        let g2 = ark_bls12_381::G2Affine::generator().into_group();
        let points = (0..len)
            .map(|index| {
                let scalar = if index % 11 == 0 {
                    Fr::zero()
                } else {
                    Fr::from((index as u64).wrapping_mul(17).wrapping_add(3))
                };
                BlsDoryG1(g1 * scalar)
            })
            .collect();
        let twists = (0..len)
            .map(|index| {
                let scalar = if index % 13 == 0 {
                    Fr::zero()
                } else {
                    Fr::from((index as u64).wrapping_mul(29).wrapping_add(5))
                };
                BlsDoryG2(g2 * scalar)
            })
            .collect();
        (points, twists)
    }

    fn serial_pair_and_add(points: &[BlsDoryG1], twists: &[BlsDoryG2]) -> BlsDoryGt {
        points
            .iter()
            .zip(twists)
            .fold(BlsDoryGt::identity(), |sum, (point, twist)| {
                sum + BlsDoryCurve::pair(point, twist)
            })
    }

    fn compressed_gt(value: &BlsDoryGt) -> Vec<u8> {
        let mut encoded = Vec::new();
        value.serialize_compressed(&mut encoded).unwrap();
        encoded
    }

    struct OpeningFixture {
        setup: DeterministicBlsDorySetup,
        commitment: BlsDoryGt,
        point: Vec<BlsDoryFr>,
        evaluation: BlsDoryFr,
        proof: DoryProof<BlsDoryG1, BlsDoryG2, BlsDoryGt>,
    }

    fn opening_fixture() -> Result<OpeningFixture, BlsDoryPrototypeError> {
        let setup = deterministic_bls_dory_setup(8)?;
        let polynomial = BlsDoryPolynomial::new(
            (0..256)
                .map(|index| BlsDoryFr::from_u64((index * index + 17 * index + 31) as u64))
                .collect(),
        )?;
        let (commitment, rows, blind) = polynomial
            .commit::<BlsDoryCurve, Transparent, BlsDoryG1Routines>(4, 4, &setup.prover)
            .map_err(|error| BlsDoryPrototypeError::Dory(error.to_string()))?;
        assert!(blind.is_zero());
        let point = (0..8)
            .map(|index| BlsDoryFr::from_u64((index * 13 + 5) as u64))
            .collect::<Vec<_>>();
        let evaluation = polynomial.evaluate(&point);
        let mut transcript = opening_transcript(&setup.identity, &commitment, &point, &evaluation);
        let (proof, hidden_evaluation) =
            prove::<_, BlsDoryCurve, BlsDoryG1Routines, BlsDoryG2Routines, _, _, Transparent>(
                &polynomial,
                &point,
                rows.clone(),
                BlsDoryFr::zero(),
                4,
                4,
                &setup.prover,
                &mut transcript,
            )
            .map_err(|error| BlsDoryPrototypeError::Dory(error.to_string()))?;
        assert!(hidden_evaluation.is_none());
        Ok(OpeningFixture {
            setup,
            commitment,
            point,
            evaluation,
            proof,
        })
    }

    #[test]
    fn deterministic_setup_has_a_pinned_identity() {
        let first = deterministic_bls_dory_setup(8).unwrap();
        let second = deterministic_bls_dory_setup(8).unwrap();
        first.validate().unwrap();
        assert_eq!(first.identity, second.identity);
        assert_eq!(first.prover.g1_vec, second.prover.g1_vec);
        assert_eq!(first.prover.g2_vec, second.prover.g2_vec);
        assert_eq!(BlsDoryFr::zero().compressed_size(), 32);
        assert_eq!(first.prover.h1.compressed_size(), 48);
        assert_eq!(first.prover.h2.compressed_size(), 96);
        assert_eq!(first.prover.ht.compressed_size(), 576);
        assert_eq!(
            first.identity,
            [
                186, 38, 244, 114, 24, 109, 242, 69, 137, 112, 134, 34, 44, 80, 154, 167, 101, 205,
                50, 143, 95, 189, 101, 85, 38, 221, 219, 96, 221, 96, 123, 231,
            ]
        );

        let mut stale_identity = first.clone();
        stale_identity.identity[0] ^= 1;
        assert!(matches!(
            stale_identity.validate(),
            Err(BlsDoryPrototypeError::InvalidSetup)
        ));

        let mut stale_verifier = first.clone();
        stale_verifier.verifier.h1 = BlsDoryG1::identity();
        assert!(matches!(
            stale_verifier.validate(),
            Err(BlsDoryPrototypeError::InvalidSetup)
        ));
        assert!(matches!(
            deterministic_bls_dory_setup(MAX_BLS_DORY_SETUP_VARIABLES + 1),
            Err(BlsDoryPrototypeError::InvalidSize)
        ));
    }

    #[test]
    fn optimized_multi_pair_is_byte_identical_to_serial_pair_and_add() {
        for len in [0, 1, 2, 3, 7, 31, 32, 33, 65, 129] {
            let (points, twists) = deterministic_pairing_inputs(len);
            let expected = serial_pair_and_add(&points, &twists);
            let actual = BlsDoryCurve::multi_pair(&points, &twists);
            assert_eq!(actual, expected, "pairing result differs at length {len}");
            assert_eq!(
                compressed_gt(&actual),
                compressed_gt(&expected),
                "canonical bytes differ at length {len}"
            );
        }
    }

    #[test]
    fn optimized_multi_pair_is_independent_of_parallel_reduction_width() {
        let (points, twists) = deterministic_pairing_inputs(129);
        let expected = serial_pair_and_add(&points, &twists);
        for threads in [1, 2, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            let actual = pool.install(|| BlsDoryCurve::multi_pair(&points, &twists));
            assert_eq!(
                compressed_gt(&actual),
                compressed_gt(&expected),
                "canonical bytes differ with {threads} Rayon threads"
            );
        }
    }

    #[test]
    #[should_panic(expected = "multi_pair requires equal length vectors")]
    fn optimized_multi_pair_rejects_mismatched_inputs() {
        let (points, mut twists) = deterministic_pairing_inputs(3);
        twists.pop();
        let _ = BlsDoryCurve::multi_pair(&points, &twists);
    }

    #[test]
    fn parallel_setup_derivation_matches_serial_index_order() {
        const VARIABLES: usize = 8;
        let generator_count = 1usize << VARIABLES.div_ceil(2);
        let g1_hasher = G1Hasher::new(G1_DOMAIN).unwrap();
        let g2_hasher = G2Hasher::new(G2_DOMAIN).unwrap();
        let serial_g1 = (0..generator_count)
            .map(|index| hash_g1(&g1_hasher, b"column-generator", index as u64))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let serial_g2 = (0..generator_count)
            .map(|index| hash_g2(&g2_hasher, b"row-generator", index as u64))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        let parallel = pool
            .install(|| deterministic_bls_dory_setup(VARIABLES))
            .unwrap();

        assert_eq!(parallel.prover.g1_vec, serial_g1);
        assert_eq!(parallel.prover.g2_vec, serial_g2);
        parallel.validate().unwrap();
    }

    #[test]
    fn transcript_challenges_use_exact_nonzero_scalar_rejection_sampling() {
        assert!(canonical_nonzero_scalar([0; 32]).is_none());

        let mut modulus = Fr::MODULUS.to_bytes_le();
        modulus.resize(32, 0);
        let modulus: [u8; 32] = modulus.try_into().unwrap();
        assert!(canonical_nonzero_scalar(modulus).is_none());

        let mut maximum = modulus;
        for byte in &mut maximum {
            if *byte != 0 {
                *byte -= 1;
                break;
            }
            *byte = u8::MAX;
        }
        assert!(canonical_nonzero_scalar(maximum).is_some());
        let mut one = [0_u8; 32];
        one[0] = 1;
        assert_eq!(canonical_nonzero_scalar(one), Some(BlsDoryFr::one()));

        let mut first = BlsDoryTranscript::new(b"sampler-test");
        first.append_bytes(b"statement", b"fixed");
        let mut second = first.clone();
        let first_challenge = first.challenge_scalar(b"challenge");
        let second_challenge = second.challenge_scalar(b"challenge");
        assert_eq!(first_challenge, second_challenge);
        assert!(!first_challenge.is_zero());

        let mut different = BlsDoryTranscript::new(b"sampler-test");
        different.append_bytes(b"statement", b"changed");
        assert_ne!(first_challenge, different.challenge_scalar(b"challenge"));
    }

    #[test]
    fn real_bls12_381_opening_round_trips_and_has_exact_size() {
        let OpeningFixture {
            setup,
            commitment,
            point,
            evaluation,
            proof,
        } = opening_fixture().unwrap();
        let mut transcript = opening_transcript(&setup.identity, &commitment, &point, &evaluation);
        verify::<_, BlsDoryCurve, BlsDoryG1Routines, BlsDoryG2Routines, _>(
            commitment,
            evaluation,
            &point,
            &proof,
            setup.verifier.clone(),
            &mut transcript,
        )
        .unwrap();
        let encoded = encode_transparent_proof(&proof).unwrap();
        assert_eq!(encoded.len(), 16_909);
    }

    #[test]
    fn statement_setup_and_proof_mutations_are_rejected() {
        let OpeningFixture {
            setup,
            commitment,
            point,
            evaluation,
            proof,
        } = opening_fixture().unwrap();

        let changed_evaluation = evaluation + BlsDoryFr::one();
        let mut transcript =
            opening_transcript(&setup.identity, &commitment, &point, &changed_evaluation);
        assert!(
            verify::<_, BlsDoryCurve, BlsDoryG1Routines, BlsDoryG2Routines, _>(
                commitment,
                changed_evaluation,
                &point,
                &proof,
                setup.verifier.clone(),
                &mut transcript,
            )
            .is_err()
        );
        let other_setup = deterministic_bls_dory_setup(10).unwrap();
        let mut transcript =
            opening_transcript(&other_setup.identity, &commitment, &point, &evaluation);
        assert!(
            verify::<_, BlsDoryCurve, BlsDoryG1Routines, BlsDoryG2Routines, _>(
                commitment,
                evaluation,
                &point,
                &proof,
                other_setup.verifier,
                &mut transcript,
            )
            .is_err()
        );

        let mut changed_proof = proof;
        changed_proof.vmv_message.c = changed_proof.vmv_message.c.scale(&BlsDoryFr::from_u64(2));
        let mut transcript = opening_transcript(&setup.identity, &commitment, &point, &evaluation);
        assert!(
            verify::<_, BlsDoryCurve, BlsDoryG1Routines, BlsDoryG2Routines, _>(
                commitment,
                evaluation,
                &point,
                &changed_proof,
                setup.verifier,
                &mut transcript,
            )
            .is_err()
        );
    }
}
