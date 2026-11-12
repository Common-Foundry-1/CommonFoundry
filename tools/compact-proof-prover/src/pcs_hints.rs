//! Fixed-size local witness hints. These never grant verifier authorization.
use anyhow::{ensure,Result};
use sha2::{Digest,Sha256};
use slop_algebra::PrimeField32 as _;
use cpu_slop_algebra::PrimeField32 as _;
use slop_challenger::IopCtx;
use sp1_gpu_utils::TestGC;
use cmfd_consensus::forgematrix_v4_basefold::ForgeMatrixV4Challenger;
const P:u32=2_130_706_433;
#[derive(Debug,PartialEq,Eq)]pub struct State{pub sponge:[u32;16],pub input:Vec<u32>,pub output:Vec<u32>}
impl State{
 pub fn gpu(c:&<TestGC as IopCtx>::Challenger)->Self{Self{sponge:c.sponge_state.map(|x|x.as_canonical_u32()),input:c.input_buffer.iter().map(|x|x.as_canonical_u32()).collect(),output:c.output_buffer.iter().map(|x|x.as_canonical_u32()).collect()}}
 pub fn cpu(c:&ForgeMatrixV4Challenger)->Self{Self{sponge:c.sponge_state.map(|x|x.as_canonical_u32()),input:c.input_buffer.iter().map(|x|x.as_canonical_u32()).collect(),output:c.output_buffer.iter().map(|x|x.as_canonical_u32()).collect()}}
 fn write(&self,out:&mut Vec<u8>)->Result<()>{
  ensure!(self.input.len()<8&&self.output.len()<=8,"hint state dimensions");
  ensure!(self.sponge.iter().chain(&self.input).chain(&self.output).all(|x|*x<P),"hint state canonicality");
  out.extend([self.input.len()as u8,self.output.len()as u8,0,0]);for x in self.sponge{out.extend(x.to_le_bytes())}
  for b in [&self.input,&self.output]{for i in 0..8{out.extend(b.get(i).copied().unwrap_or(0).to_le_bytes())}}Ok(())
 }
}
pub struct PcsStates{pub bank:usize,pub before:State,pub after:State}
pub fn encode(raw:&[u8],states:&[PcsStates])->Result<Vec<u8>>{
 ensure!(raw.len()==12_025_320&&states.len()==3,"hint proof/count dimensions");
 let mut out=Vec::with_capacity(832);out.extend(b"CMFDPST1");out.extend(Sha256::digest(raw));
 for (bank,s) in states.iter().enumerate(){ensure!(s.bank==bank,"hint bank order");s.before.write(&mut out)?;s.after.write(&mut out)?;}
 ensure!(out.len()==832,"hint encoding size");Ok(out)
}
#[cfg(test)]mod tests{
 use super::*;
 fn state()->State{State{sponge:[0;16],input:vec![],output:vec![1;8]}}
 #[test]fn reject_noncanonical_or_oversized_states_and_bad_bank_order(){
  let mut out=Vec::new();let mut s=state();s.input=vec![0;8];assert!(s.write(&mut out).is_err());
  let mut s=state();s.output.push(0);assert!(s.write(&mut out).is_err());let mut s=state();s.sponge[2]=P;assert!(s.write(&mut out).is_err());
  let raw=vec![0;12_025_320];let states=(0..3).map(|bank|PcsStates{bank,before:state(),after:state()}).collect::<Vec<_>>();assert_eq!(encode(&raw,&states).unwrap().len(),832);
  let mut bad=states;bad.swap(0,1);assert!(encode(&raw,&bad).is_err());assert!(encode(&raw[..12],&bad).is_err());
 }
}
