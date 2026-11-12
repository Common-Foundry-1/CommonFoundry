//! Independent research verifier for the all-relations-first transcript.
use super::*;
use cmfd_consensus::forgematrix_v4_basefold::verify_forgematrix_v4_opening_reduction;
pub fn verify(statement:ForgeMatrixV4TranscriptStatement,fixed:[CpuDigest;3],base:&[u8],proof:&ForgeMatrixV4TransparentProof)->Result<()> {
 ensure!(base.len()==524_288&&proof.final_activation.len()==524_288,"foundation activation shape");ensure!(base.iter().all(|x|*x<=250),"foundation base input range");ensure!(forgematrix_v4_final_activation_digest(statement.challenge_digest,&proof.final_activation)==statement.final_activation_digest,"foundation final digest");
 let dynamic=std::array::from_fn(|bank|proof.banks[bank].dynamic_commitment);let mut challenger=forgematrix_v4_transcript(statement);bind_forgematrix_v4_commitments(&mut challenger,&fixed,&dynamic);let mut claims:[Vec<CpuOpeningClaim>;3]=std::array::from_fn(|_|Vec::with_capacity(16));
 // Every existing relation check, with no opening proof interleaved.
 for bank in 0..3 {for repetition in 0..2 {
  let relation=&proof.banks[bank].relations[repetition];let matrix_point=sample_forgematrix_v4_matrix_point(&mut challenger,bank,repetition)?;let mask=forgematrix_v4_mask_evaluation(statement.challenge_digest,bank,&matrix_point.layer,&matrix_point.batch,&matrix_point.output)?;verify_forgematrix_v4_matrix_relation(&matrix_point,mask,&relation.matrix,&mut challenger)?;let terminal=forgematrix_v4_matrix_terminal_layer(&relation.matrix)?;verify_forgematrix_v4_shift_relation(&terminal,relation.matrix.input_evaluation,&relation.shift,&mut challenger)?;claims[bank].extend(forgematrix_v4_matrix_opening_claims(&matrix_point,&relation.matrix)?);claims[bank].push(forgematrix_v4_shift_opening_claim(&matrix_point,&relation.matrix,&relation.shift)?);let boundary=forgematrix_v4_shift_boundary_point(&matrix_point,&relation.matrix)?;
  if bank==0{let expected=forgematrix_v4_initial_activation_evaluation(statement.challenge_digest,base,&boundary.batch,&boundary.output)?;ensure!(relation.shift.boundary_evaluation==expected,"foundation initial boundary");}else{claims[bank-1].push(forgematrix_v4_shift_boundary_opening_claim(&matrix_point,&relation.matrix,&relation.shift)?);}
  let cubic_point=sample_forgematrix_v4_cubic_point(&mut challenger,bank,repetition)?;verify_forgematrix_v4_cubic_relation(&cubic_point,&relation.cubic,&mut challenger)?;claims[bank].extend(forgematrix_v4_cubic_opening_claims(&relation.cubic)?);
 }}
 for repetition in 0..2{let point=sample_forgematrix_v4_final_point(&mut challenger,repetition)?;let value=forgematrix_v4_activation_evaluation(&proof.final_activation,&point.batch,&point.output)?;claims[2].push(forgematrix_v4_final_opening_claim(&point,value)?);}
 for bank in 0..3{finalize_forgematrix_v4_bank_opening_claims(&mut claims[bank])?;verify_forgematrix_v4_opening_reduction([fixed[bank],dynamic[bank]],&claims[bank],&proof.banks[bank].opening,&mut challenger)?;}
 Ok(())
}
