use anyhow::{ensure,Result};
use slop_tensor::{Tensor,TensorView};
use sp1_gpu_cudart::{args,DeviceTensor,TaskScope};
use sp1_gpu_sys::runtime::KernelPtr;
use sp1_gpu_utils::{Ext,Felt};
unsafe extern "C"{fn cmfd_batch_layer_reduction_kernel()->KernelPtr;}
pub fn checked_shape(input:usize,coefficients:usize,layers:usize,batch:usize,width:usize)->Result<usize>{
 ensure!(layers>0&&batch>0&&width>0,"empty reduction shape");
 let output=layers.checked_mul(width).ok_or_else(||anyhow::anyhow!("reduction output overflow"))?;
 let total=output.checked_mul(batch).ok_or_else(||anyhow::anyhow!("reduction input overflow"))?;
 ensure!(input==total&&coefficients==batch,"reduction input/coefficient shape mismatch");
 ensure!(output.div_ceil(256)<=u32::MAX as usize,"reduction launch overflow");
 Ok(output)
}
pub fn reduce(src:TensorView<'_,Felt,TaskScope>,coefficients:&[Ext],layers:usize,batch:usize,width:usize,scope:&TaskScope)->Result<Vec<Ext>>{
 let count=checked_shape(src.total_len(),coefficients.len(),layers,batch,width)?;
 ensure!(size_of::<Felt>()==4&&size_of::<Ext>()==16,"reduction field ABI mismatch");
 let coefficients=DeviceTensor::from_host(&Tensor::from(coefficients.to_vec()),scope)?;
 let mut output=DeviceTensor::<Ext>::with_sizes_in([layers,width],scope.clone());
 unsafe{
  output.assume_init();
  let args=args!(src.as_ptr(),coefficients.as_ptr(),output.as_mut_ptr(),layers,batch,width);
  scope.launch_kernel(cmfd_batch_layer_reduction_kernel(),u32::try_from(count.div_ceil(256))?,256u32,&args,0)?;
 }
 scope.synchronize_blocking()?;
 Ok(output.to_host()?.into_buffer().into_vec())
}
#[cfg(test)]mod tests{
 use super::*;
 #[test]fn trusted_shape_is_checked_before_any_device_access(){
  assert_eq!(checked_shape(128*128*4096,128,128,128,4096).unwrap(),128*4096);
  assert_eq!(checked_shape(3*7*259,7,3,7,259).unwrap(),3*259);
  for shape in [(0,0,0,0,0),(1,1,1,1,0),(1024,127,1,128,8),(1023,128,1,128,8),(usize::MAX,1,usize::MAX,1,2),(usize::MAX,1,1,usize::MAX,2)]{
   assert!(checked_shape(shape.0,shape.1,shape.2,shape.3,shape.4).is_err());
  }
 }
}
