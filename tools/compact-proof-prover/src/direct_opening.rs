//! Production-size direct six-commitment opening prototype.
//! This emits a private research artifact; it is not a consensus decoder.
use super::*;
use cmfd_consensus::forgematrix_v4_direct::reduction as direct;
use slop_algebra::AbstractExtensionField;
use slop_challenger::GrindingChallenger;
use slop_commit::Rounds;
use sp1_gpu_basefold::CudaStackedPcsProverData;
use sp1_gpu_merkle_tree::MerkleTree;
use sp1_gpu_jagged_sumcheck::multi_hadamard_sumcheck_at_points;

const DIRECT_DOMAIN:&[u8]=b"CommonFoundry/Research/DirectSixOpening/v1";
pub(crate) const PCS_DOMAIN:&[u8]=b"CommonFoundry/Research/DirectSixOpening/SharedPCS/v1";
const DEFAULT_GPU_BUDGET:usize=13<<30;

pub(crate) fn observe_ext(challenger:&mut GpuChallenger,value:Ext){let fields:&[Felt]=value.as_base_slice();for x in fields{challenger.observe(*x)}}
pub(crate) fn tag(challenger:&mut GpuChallenger,bytes:&[u8]){challenger.observe(Felt::from_canonical_usize(bytes.len()));for byte in bytes{challenger.observe(Felt::from_canonical_u8(*byte));}}
fn active_gpu_budget(total:usize)->Result<usize>{
 let Ok(requested)=std::env::var("CMFD_DIRECT_PILOT_GPU_BUDGET_GIB")else{return Ok(DEFAULT_GPU_BUDGET)};
 let gib=requested.parse::<usize>()?;
 ensure!(total>=24<<30&&(13..=24).contains(&gib),"pilot GPU budget override requires a 24+ GiB card and a 13-24 GiB cap");
 Ok(gib<<30)
}
fn budget(label:&str,peak:&mut usize)->Result<usize>{let(free,total)=cuda_memory_info()?;let used=total-free;*peak=(*peak).max(used);let limit=active_gpu_budget(total)?;ensure!(used<=limit,"{label} exceeded the configured GPU budget ({} GiB)",limit>>30);eprintln!("direct_gpu_stage={label} used_bytes={used} guard_bytes={limit}");Ok(used)}
pub(crate) fn direct_start(job:[u8;32],roots:&[GpuDigest;6],points:&[Vec<Ext>;3],evaluations:&[Vec<Ext>;6])->(GpuChallenger,Felt,Vec<Ext>,Ext){
 let mut c=TestGC::default_challenger();tag(&mut c,DIRECT_DOMAIN);c.observe(Felt::from_canonical_usize(LOG_ROWS as usize));c.observe(Felt::from_canonical_usize(6));for n in [256usize,16,256,16,256,16]{c.observe(Felt::from_canonical_usize(n));}for b in job{c.observe(Felt::from_canonical_u8(b));}for root in roots{c.observe(*root)}for point in points{for x in point{observe_ext(&mut c,*x)}}for values in evaluations{for x in values{observe_ext(&mut c,*x)}}
 let witness=c.grind(slop_basefold::BATCH_GRINDING_BITS);let n=816usize.next_power_of_two();let point=sample_point(&mut c,n.ilog2()as usize);let weights=Mle::<Ext>::partial_lagrange(&point).guts().as_slice().to_vec();let claim=evaluations.iter().flatten().zip(&weights).map(|(v,w)|*v**w).sum();(c,witness,weights,claim)
}
pub(crate) fn fixed_data(maps:&real_v4_opening::FixedArtifactMaps,scope:&TaskScope)->CudaStackedPcsProverData<TestGC>{CudaStackedPcsProverData{merkle_tree_tcs_data:(MerkleTree{digests:Buffer::with_capacity_in(0,scope.clone()),height:24,stored_height:0},maps.root,24,256),codeword_mle:None}}
pub(crate) fn direct_statement(prepared:&PreparedProver,statement:ForgeMatrixV4TranscriptStatement,proof:&ForgeMatrixV4TransparentProof)->Result<(direct::Statement,[GpuDigest;6],[Vec<Ext>;3],[Vec<Ext>;6])>{
 let cpu_roots: [CpuDigest;6]=std::array::from_fn(|i|if i%2==0{prepared.cpu_fixed[i/2]}else{proof.banks[i/2].dynamic_commitment});
 let gpu_roots:[GpuDigest;6]=bridge(cpu_roots)?;
 let cpu_points:[Vec<CpuExt>;3]=std::array::from_fn(|i|proof.banks[i].opening.sumcheck.point_and_eval.0.iter().copied().collect());
 let gpu_points:[Vec<Ext>;3]=bridge(cpu_points.clone())?;
 let cpu_evaluations:[Vec<CpuExt>;6]=std::array::from_fn(|i|if i%2==0{proof.banks[i/2].opening.fixed_column_evaluations.clone()}else{proof.banks[i/2].opening.dynamic_column_evaluations.clone()});
 let gpu_evaluations:[Vec<Ext>;6]=bridge(cpu_evaluations.clone())?;
 let lab=direct::Statement{shape:direct::Shape::production(),job:statement.digest(),roots:bridge(cpu_roots)?,bank_points:bridge(cpu_points)?,original_evaluations:bridge(cpu_evaluations)?};Ok((lab,gpu_roots,gpu_points,gpu_evaluations))
}

pub fn prove(
 prepared:&PreparedProver,statement:ForgeMatrixV4TranscriptStatement,original:&ForgeMatrixV4TransparentProof,
 dynamic_traces:PreparedDynamicTraces,output:&Path,scope:&TaskScope,
)->Result<serde_json::Value>{
  prove_impl(prepared,statement,original,dynamic_traces,std::array::from_fn(|_|None),output,scope,false,true)
}

pub fn prove_integrated(
 prepared:&PreparedProver,statement:ForgeMatrixV4TranscriptStatement,public_carrier:&ForgeMatrixV4TransparentProof,
  dynamic_traces:PreparedDynamicTraces,fixed_banks:[Option<DeviceBuffer<u8>>;3],output:&Path,scope:&TaskScope,self_check:bool,
)->Result<serde_json::Value>{
  prove_impl(prepared,statement,public_carrier,dynamic_traces,fixed_banks,output,scope,true,self_check)
}

fn prove_impl(
 prepared:&PreparedProver,statement:ForgeMatrixV4TranscriptStatement,original:&ForgeMatrixV4TransparentProof,
  dynamic_traces:PreparedDynamicTraces,preloaded_fixed:[Option<DeviceBuffer<u8>>;3],output:&Path,scope:&TaskScope,integrated:bool,self_check:bool,
)->Result<serde_json::Value>{
 let began=Instant::now();let mut peak=0;budget("start",&mut peak)?;
 let(lab,roots,points,evaluations)=direct_statement(prepared,statement,original)?;
 let(mut challenger,batch_witness,weights,claimed_sum)=direct_start(lab.job,&roots,&points,&evaluations);
  let secondary_inputs_started=Instant::now();let fixed_upload_started=Instant::now();
  // Keep bank 2 from relation proving. Rotate one additional bank through
  // reductions and shared evaluations; no more than two fixed banks are live.
  // Reordering the independent column evaluations does not observe or sample
  // the transcript: assemble the same six values in their canonical order.
  let reused_fixed_banks=preloaded_fixed.iter().any(Option::is_some);
  let mut fixed_banks=preloaded_fixed;
  scope.synchronize_blocking()?;let mut fixed_initial_upload_seconds=fixed_upload_started.elapsed().as_secs_f64();budget("fixed-bank-storage-ready",&mut peak)?;
  let mut traces=Vec::with_capacity(6);let mut claims=Vec::with_capacity(6);let mut offset=0;
 for bank in 0..3{
   let upload_started=Instant::now();
   if fixed_banks[bank].is_none(){fixed_banks[bank]=Some(DeviceBuffer::from_host_slice(&prepared.encoded_banks[bank],scope)?);}
   scope.synchronize_blocking()?;fixed_initial_upload_seconds+=upload_started.elapsed().as_secs_f64();
   let fixed=fixed_banks[bank].as_ref().expect("secondary fixed bank");
   budget("secondary-fixed-bank",&mut peak)?;
   let fixed_weights=&weights[offset..offset+256];traces.push(real_v4_opening::fixed_bank_rlc(fixed,fixed_weights,scope)?);claims.push(evaluations[2*bank].iter().zip(fixed_weights).map(|(v,w)|*v**w).sum());offset+=256;scope.synchronize_blocking()?;
  let dynamic_weights=&weights[offset..offset+16];let coefficients=DeviceTensor::from_host(&Tensor::from(dynamic_weights.to_vec()),scope)?;let row=dot_along_dim_view(dynamic_traces[bank].main_virtual_tensor(LOG_ROWS),coefficients.as_view(),0);traces.push(Mle::new(row.reshape([1,ROWS])));claims.push(evaluations[2*bank+1].iter().zip(dynamic_weights).map(|(v,w)|*v**w).sum());offset+=16;budget("secondary-inputs",&mut peak)?;
   scope.synchronize_blocking()?;if bank==0{drop(fixed_banks[bank].take());}scope.synchronize_blocking()?;
 }
  let secondary_inputs_seconds=secondary_inputs_started.elapsed().as_secs_f64();ensure!(claims.iter().copied().sum::<Ext>()==claimed_sum,"secondary claimed sum mismatch");let eq_points=(0..6).map(|i|Point::from(points[i/2].clone())).collect::<Vec<_>>();let reduction_started=Instant::now();
 let(sumcheck,_)=multi_hadamard_sumcheck_at_points(traces,&eq_points,claims,&mut challenger,claimed_sum);scope.synchronize_blocking()?;let reduction_seconds=reduction_started.elapsed().as_secs_f64();budget("secondary-complete",&mut peak)?;
  let shared_started=Instant::now();let shared_point=sumcheck.point_and_eval.0.clone();let mut shared:[Vec<Ext>;6]=std::array::from_fn(|_|Vec::new());
 for bank in [1usize,0,2]{
   if fixed_banks[bank].is_none(){fixed_banks[bank]=Some(DeviceBuffer::from_host_slice(&prepared.encoded_banks[bank],scope)?);}
   let fixed=fixed_banks[bank].as_ref().expect("shared fixed bank");
   shared[2*bank]=real_v4_opening::evaluate_fixed_columns(fixed,&shared_point,scope)?;scope.synchronize_blocking()?;
   shared[2*bank+1]=real_v4_opening::evaluate_dynamic_columns(dynamic_traces[bank].main_virtual_tensor(LOG_ROWS),&shared_point,scope)?;budget("shared-evaluations",&mut peak)?;
   scope.synchronize_blocking()?;drop(fixed_banks[bank].take());scope.synchronize_blocking()?;
 }
  let shared_seconds=shared_started.elapsed().as_secs_f64();drop(fixed_banks);scope.synchronize_blocking()?;budget("fixed-banks-released",&mut peak)?;let gpu_shared=shared;
 let rounds=sumcheck.univariate_polys.iter().map(|poly|{ensure!(poly.coefficients.len()==3,"secondary round degree");bridge([poly.coefficients[0],poly.coefficients[1],poly.coefficients[2]])}).collect::<Result<Vec<_>>>()?;
 let reduction=direct::ReductionProof{batch_witness:bridge(batch_witness)?,rounds,evaluations_at_shared_point:bridge(gpu_shared.clone())?};let obligation=direct::verify_reduction(&lab,&reduction)?;ensure!(obligation.point()==bridge::<_,Vec<_>>(shared_point.iter().copied().collect::<Vec<_>>())?.as_slice(),"CPU/GPU shared point mismatch");ensure!(obligation.values()==&bridge::<_,[Vec<_>;6]>(gpu_shared.clone())?,"CPU/GPU shared evaluations mismatch");
 // Recommit the three dynamic traces and retain their codewords/trees for one joint BaseFold.
  let recommit_started=Instant::now();let prover=FriCudaProver::<TestGC,_,Felt>::new(Poseidon2SP1Field16CudaProver::new(scope),FriConfig::new(LOG_BLOWUP,QUERIES,POW_BITS),LOG_ROWS);let mut dynamic_data=Vec::new();
 for bank in 0..3{let(_,data)=commit_multilinears::<TestGC,_>(&dynamic_traces[bank],LOG_ROWS,false,false,&prover)?;scope.synchronize_blocking()?;ensure!(data.original_commitment==roots[2*bank+1],"dynamic commitment mismatch");dynamic_data.push(data);budget("dynamic-recommit",&mut peak)?;}
  let dynamic_recommit_seconds=recommit_started.elapsed().as_secs_f64();let fixed_data=(0..3).map(|bank|fixed_data(&prepared.fixed_maps[bank],scope)).collect::<Vec<_>>();let mut refs=Vec::with_capacity(6);for bank in 0..3{refs.push(&fixed_data[bank]);refs.push(&dynamic_data[bank].pcs_prover_data);}let stacked:Rounds<_>=refs.into_iter().collect();
 let encoded=&prepared.encoded_banks;let traces_ref=&dynamic_traces;let builder=Box::new(move|coefficients:&Tensor<Ext>,builder_scope:&TaskScope|{
  let mut at=0;let mut combined:Option<Mle<Ext,TaskScope>>=None;
  for bank in 0..3{
   let fixed=DeviceBuffer::from_host_slice(&encoded[bank],builder_scope).expect("direct fixed upload");let part=real_v4_opening::fixed_bank_rlc(&fixed,&coefficients.as_slice()[at..at+256],builder_scope).expect("direct fixed RLC");at+=256;
   if let Some(current)=combined.as_mut(){real_v4_opening::add_ext_in_place(current,part.guts(),builder_scope).expect("direct fixed add");}else{combined=Some(part)}builder_scope.synchronize_blocking().expect("direct fixed sync");drop(fixed);
   let c=DeviceTensor::from_host(&Tensor::from(coefficients.as_slice()[at..at+16].to_vec()),builder_scope).expect("direct dynamic coefficients");at+=16;let part=dot_along_dim_view(traces_ref[bank].main_virtual_tensor(LOG_ROWS),c.as_view(),0);real_v4_opening::add_ext_in_place(combined.as_mut().unwrap(),&part,builder_scope).expect("direct dynamic add");builder_scope.synchronize_blocking().expect("direct dynamic sync");
  }assert_eq!(at,816);combined.unwrap()
 });
 let builders=vec![Some(prepared.fixed_maps[0].opening_builder()),None,Some(prepared.fixed_maps[1].opening_builder()),None,Some(prepared.fixed_maps[2].opening_builder()),None];
 tag(&mut challenger,PCS_DOMAIN);for x in shared_point.iter(){observe_ext(&mut challenger,*x)}for values in &gpu_shared{for x in values{observe_ext(&mut challenger,*x)}}
 let flat=gpu_shared.iter().flatten().copied().collect::<Vec<_>>();let pcs_started=Instant::now();let basefold=prover.prove_trusted_evaluations_basefold_with_component_openings(shared_point.clone(),flat,None,Some(builder),stacked,Some(builders),&mut challenger)?;scope.synchronize_blocking()?;let pcs_seconds=pcs_started.elapsed().as_secs_f64();budget("joint-basefold-complete",&mut peak)?;
  let bridge_started=Instant::now();let gpu_basefold_bytes=bincode::serialize(&basefold)?;let cpu_basefold=direct::decode_basefold(&gpu_basefold_bytes)?;let bridge_seconds=bridge_started.elapsed().as_secs_f64();
  // The complete direct verifier below rechecks the same BaseFold proof and
  // reduction against the public relation transcript. Keep the early PCS-only
  // check for the older fixture-driven prototype, which has no full verifier.
  if !integrated{let _verified=obligation.verify_basefold(&cpu_basefold)?;}
  let consensus_reduction:cmfd_consensus::forgematrix_v4_direct::ReductionProof=bridge(&reduction)?;
  let consensus_basefold:cmfd_consensus::forgematrix_v4_direct::DirectBasefoldProof=bincode::deserialize(&gpu_basefold_bytes)?;
  let encoding_started=Instant::now();let wire=cmfd_consensus::forgematrix_v4_direct::encode(original,statement,&consensus_reduction,&consensus_basefold)?;let encoding_seconds=encoding_started.elapsed().as_secs_f64();
  // The pool server passes self_check=false, as in the original prover. Its
  // untrusted output must still pass the node's complete consensus verifier.
  // Standalone qualification retains the independent full CPU self-check.
  let verify_started=Instant::now();if integrated&&self_check{cmfd_consensus::forgematrix_v4_direct::verify_wire(statement,prepared.cpu_fixed,&prepared.base_input,&wire)?;}else{cmfd_consensus::forgematrix_v4_direct::decode(&wire,statement)?;}let selfcontained_verify_seconds=verify_started.elapsed().as_secs_f64();
  let reduction_bytes=bincode::serialize(&reduction)?;let raw_basefold_bytes=gpu_basefold_bytes.len();let compressed_basefold_bytes=wire.len()-cmfd_consensus::forgematrix_v4_direct::HEADER_BYTES-cmfd_consensus::forgematrix_v4_direct::PUBLIC_BYTES-reduction_bytes.len();
 std::fs::OpenOptions::new().create_new(true).write(true).open(output)?.write_all(&wire)?;
  let guard_gib=active_gpu_budget(cuda_memory_info()?.1)?>>30;
  let report=serde_json::json!({"schema":if integrated{"CMFD_DIRECT_SELFCONTAINED_GPU_RESEARCH_V3"}else{"CMFD_DIRECT_SIX_OPENING_GPU_PROTOTYPE_V3"},"verified":!integrated||self_check,"node_verification_required":integrated&&!self_check,"relation_checks_completed":true,"selfcontained_verified":integrated&&self_check,"producer_self_check_requested":self_check,"selfcontained_verify_seconds":selfcontained_verify_seconds,"wire_bytes":wire.len(),"secondary_reduction_bytes":reduction_bytes.len(),"raw_joint_basefold_bytes":raw_basefold_bytes,"compressed_joint_basefold_bytes":compressed_basefold_bytes,"reused_fixed_banks":reused_fixed_banks,"fixed_initial_upload_seconds":fixed_initial_upload_seconds,"secondary_inputs_seconds":secondary_inputs_seconds,"reduction_seconds":reduction_seconds,"shared_evaluations_seconds":shared_seconds,"dynamic_recommit_seconds":dynamic_recommit_seconds,"joint_basefold_seconds":pcs_seconds,"bridge_seconds":bridge_seconds,"encoding_seconds":encoding_seconds,"direct_stage_seconds":began.elapsed().as_secs_f64(),"peak_sampled_gpu_bytes":peak,"absolute_gpu_guard_gib":guard_gib,"original_field_parameters":{"log_blowup":1,"queries":270,"grinding_bits":16,"commitments":6},"original_full_proof_used_only_as_valid_fixture_input":!integrated,"production_consensus_or_admission_implemented":false,"overall_security_qualified":false});eprintln!("CMFD_DIRECT_PROFILE {}",report);std::fs::write(output.with_extension("result.json"),serde_json::to_vec_pretty(&report)?)?;Ok(report)
}
