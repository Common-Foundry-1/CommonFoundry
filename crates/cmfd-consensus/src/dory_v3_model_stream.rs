//! Typed publication boundary for streaming an authenticated Dory V3 model.
//!
//! A caller cannot select a loose manifest or legacy model identity here. The
//! exact manifest, role layout, setup identity, and Dory identity all come
//! from the non-serializable Record V2 capability produced after a complete
//! model-bank authentication pass.

use std::io::Read;

use thiserror::Error;

use crate::{
    dory_bls12_381_prototype::DeterministicBlsDorySetup,
    dory_v3_model::DoryV3ModelIdentityV1,
    dory_v3_model_record::{
        BankAuthenticatedDoryV3ModelCommitmentRecordV2, DoryV3ModelCommitmentRecordError,
    },
    dory_v3_suite::Digest32,
    model_bank::{
        ModelBankError, ModelBankFieldStreamError, ModelBankManifest, ModelFieldChunk,
        ModelPcsRoleLayout, StagedModelFieldLayoutSink, VerifiedModelBankLayoutReceipt,
        verify_model_bank_into_staged_field_layout_sink,
    },
};

/// Publication receipt for model fields streamed under one authenticated
/// Dory V3 Record V2 capability.
///
/// Fields are private so callers cannot turn a serialized Record V2 or loose
/// model digest into authority to publish staged model state.
#[derive(Debug)]
pub struct VerifiedBankAuthenticatedDoryV3ModelReceipt {
    manifest: ModelBankManifest,
    layout: ModelPcsRoleLayout,
    record_digest: Digest32,
    model_identity_digest: Digest32,
    model_identity: DoryV3ModelIdentityV1,
}

impl VerifiedBankAuthenticatedDoryV3ModelReceipt {
    #[must_use]
    pub const fn manifest(&self) -> &ModelBankManifest {
        &self.manifest
    }

    #[must_use]
    pub const fn layout(&self) -> ModelPcsRoleLayout {
        self.layout
    }

    #[must_use]
    pub const fn record_digest(&self) -> Digest32 {
        self.record_digest
    }

    #[must_use]
    pub const fn model_identity_digest(&self) -> Digest32 {
        self.model_identity_digest
    }

    #[must_use]
    pub const fn model_identity(&self) -> &DoryV3ModelIdentityV1 {
        &self.model_identity
    }

    /// Return true only for the exact bank-authenticated Record V2 capability
    /// that authorized this publication.
    #[must_use]
    pub fn is_bound_to_bank_authenticated_record(
        &self,
        authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    ) -> bool {
        let record = authenticated.record();
        self.record_digest == record.record_digest()
            && self.model_identity_digest == record.model_identity_digest()
            && self.manifest == *record.manifest()
            && self.model_identity == *record.model_identity()
    }
}

/// Transactional sink for canonical Dory V3 model-field chunks.
///
/// Implementations must keep all state provisional until `finish_verified`.
/// That method is the only point at which a resident model may be published.
pub trait StagedDoryV3ModelFieldSink: Sized {
    type Error: std::error::Error + 'static;
    type Output;

    fn write_chunk(&mut self, chunk: ModelFieldChunk<'_>) -> Result<(), Self::Error>;

    fn finish_verified(
        self,
        receipt: VerifiedBankAuthenticatedDoryV3ModelReceipt,
    ) -> Result<Self::Output, Self::Error>;
}

/// Fail-closed errors from the authenticated Dory V3 staged stream.
#[derive(Debug, Error)]
pub enum BankAuthenticatedDoryV3ModelFieldStreamError<E>
where
    E: std::error::Error + 'static,
{
    #[error("Dory V3 Record V2 authority is invalid: {0}")]
    Authority(#[source] DoryV3ModelCommitmentRecordError),
    #[error("model-bank verification failed: {0}")]
    ModelBank(#[source] ModelBankError),
    #[error("staged Dory V3 model-field sink failed: {0}")]
    Sink(#[source] E),
}

/// Reauthenticate one model-bank reader and publish staged fields only under
/// the exact bank-authenticated production Record V2 capability.
///
/// Record/setup/production checks run before the reader or sink is touched.
/// The reader then authenticates the complete header, payload roots, exact
/// length, and EOF before the sink receives its publication receipt.
pub fn verify_dory_v3_model_bank_into_staged_field_sink<R, S>(
    reader: R,
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    setup: &DeterministicBlsDorySetup,
    sink: S,
) -> Result<S::Output, BankAuthenticatedDoryV3ModelFieldStreamError<S::Error>>
where
    R: Read,
    S: StagedDoryV3ModelFieldSink,
{
    verify_dory_v3_model_bank_into_staged_field_sink_inner(reader, authenticated, setup, sink, true)
}

#[cfg(test)]
pub(crate) fn verify_dory_v3_model_bank_into_staged_field_sink_for_test<R, S>(
    reader: R,
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    setup: &DeterministicBlsDorySetup,
    sink: S,
) -> Result<S::Output, BankAuthenticatedDoryV3ModelFieldStreamError<S::Error>>
where
    R: Read,
    S: StagedDoryV3ModelFieldSink,
{
    verify_dory_v3_model_bank_into_staged_field_sink_inner(
        reader,
        authenticated,
        setup,
        sink,
        false,
    )
}

fn verify_dory_v3_model_bank_into_staged_field_sink_inner<R, S>(
    reader: R,
    authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    setup: &DeterministicBlsDorySetup,
    sink: S,
    require_production: bool,
) -> Result<S::Output, BankAuthenticatedDoryV3ModelFieldStreamError<S::Error>>
where
    R: Read,
    S: StagedDoryV3ModelFieldSink,
{
    let record = authenticated.record();
    if require_production {
        record
            .validate_production(setup)
            .map_err(BankAuthenticatedDoryV3ModelFieldStreamError::Authority)?;
    } else {
        validate_fixture_record_setup(record, setup)
            .map_err(BankAuthenticatedDoryV3ModelFieldStreamError::Authority)?;
    }
    let identity = record.model_identity();
    let weight_bank_count = identity.weight_bank_count().map_err(|error| {
        BankAuthenticatedDoryV3ModelFieldStreamError::Authority(
            DoryV3ModelCommitmentRecordError::ModelIdentity(error),
        )
    })?;
    let adapter = DoryV3SinkAdapter {
        sink,
        record_digest: record.record_digest(),
        model_identity_digest: record.model_identity_digest(),
        model_identity: identity.clone(),
    };
    verify_model_bank_into_staged_field_layout_sink(
        reader,
        record.manifest(),
        identity.layers_per_bank(),
        weight_bank_count,
        adapter,
    )
    .map_err(|error| match error {
        ModelBankFieldStreamError::ModelBank(error) => {
            BankAuthenticatedDoryV3ModelFieldStreamError::ModelBank(error)
        }
        ModelBankFieldStreamError::Sink(error) => {
            BankAuthenticatedDoryV3ModelFieldStreamError::Sink(error)
        }
    })
}

fn validate_fixture_record_setup(
    record: &crate::dory_v3_model_record::DoryV3ModelCommitmentRecordV2,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), DoryV3ModelCommitmentRecordError> {
    record.validate()?;
    setup
        .validate()
        .map_err(|_| DoryV3ModelCommitmentRecordError::InvalidSetup)?;
    if record.setup_identity().into_bytes() != setup.identity() {
        return Err(DoryV3ModelCommitmentRecordError::SetupIdentityMismatch);
    }
    if usize::try_from(record.padded_variables()).ok() != Some(setup.max_log_n()) {
        return Err(DoryV3ModelCommitmentRecordError::PaddedVariablesMismatch);
    }
    Ok(())
}

struct DoryV3SinkAdapter<S> {
    sink: S,
    record_digest: Digest32,
    model_identity_digest: Digest32,
    model_identity: DoryV3ModelIdentityV1,
}

impl<S> StagedModelFieldLayoutSink for DoryV3SinkAdapter<S>
where
    S: StagedDoryV3ModelFieldSink,
{
    type Error = S::Error;
    type Output = S::Output;

    fn write_chunk(&mut self, chunk: ModelFieldChunk<'_>) -> Result<(), Self::Error> {
        self.sink.write_chunk(chunk)
    }

    fn finish_verified(
        self,
        receipt: VerifiedModelBankLayoutReceipt,
    ) -> Result<Self::Output, Self::Error> {
        self.sink
            .finish_verified(VerifiedBankAuthenticatedDoryV3ModelReceipt {
                manifest: *receipt.manifest(),
                layout: receipt.layout(),
                record_digest: self.record_digest,
                model_identity_digest: self.model_identity_digest,
                model_identity: self.model_identity,
            })
    }
}
