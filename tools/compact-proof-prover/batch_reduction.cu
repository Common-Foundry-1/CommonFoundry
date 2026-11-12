#include "config.cuh"
#include <cstddef>
static_assert(sizeof(kb31_t)==4,"base field ABI");
static_assert(sizeof(ext_t)==16,"extension field ABI");

// Input layout is [layer][batch][column], identical to the validated trace.
// Each output is exactly the existing base/extension dot product for one layer.
__global__ void cmfdBatchLayerReduction(
    const kb31_t* __restrict__ input,
    const ext_t* __restrict__ coefficients,
    ext_t* __restrict__ output,
    size_t layers,size_t batch,size_t width) {
    const size_t index=static_cast<size_t>(blockIdx.x)*blockDim.x+threadIdx.x;
    if(index>=layers*width)return;
    const size_t layer=index/width,column=index%width;
    ext_t sum=ext_t::zero();
    for(size_t row=0;row<batch;++row){
        sum+=ext_t::load(coefficients,row)*kb31_t::load(input,(layer*batch+row)*width+column);
    }
    ext_t::store(output,index,sum);
}
extern "C" void* cmfd_batch_layer_reduction_kernel(){return (void*)cmfdBatchLayerReduction;}

// Exact fixed-shape metadata and input checks; no proof parameters change.
namespace cmfd_v4_resident {
__global__ void traceLayout(kb31_t* dense,uint32_t* column_index,size_t rows,size_t columns) {
    const size_t entries=rows*columns/2;
    for(size_t i=size_t(blockIdx.x)*blockDim.x+threadIdx.x;i<entries;i+=size_t(blockDim.x)*gridDim.x) {
        column_index[i]=static_cast<uint32_t>(i/(rows/2));
        if(i<rows) kb31_t::store(dense,i,kb31_t::zero());
    }
}
__global__ void validateWords(const uint32_t* words,size_t count,uint32_t* invalid) {
    for(size_t i=size_t(blockIdx.x)*blockDim.x+threadIdx.x;i<count;i+=size_t(blockDim.x)*gridDim.x)
        if(words[i]>=0x7f000001u)atomicExch(invalid,1u);
}
__global__ void deriveActivations(const kb31_t* pre,kb31_t* act,size_t count) {
    for(size_t i=size_t(blockIdx.x)*blockDim.x+threadIdx.x;i<count;i+=size_t(blockDim.x)*gridDim.x) {
        const auto value=kb31_t::load(pre,i);
        kb31_t::store(act,i,value*value*value);
    }
}
__global__ void validateLifts(const uint32_t* base,const uint32_t* pre,const uint32_t* next,size_t count,uint32_t* invalid) {
    for(size_t i=size_t(blockIdx.x)*blockDim.x+threadIdx.x;i<count;i+=size_t(blockDim.x)*gridDim.x){
        if(pre&&(pre[4*i]!=base[i]||pre[4*i+1]||pre[4*i+2]||pre[4*i+3]))atomicOr(invalid,1u);
        if(next&&(next[4*i]!=base[count+i]||next[4*i+1]||next[4*i+2]||next[4*i+3]))atomicOr(invalid,2u);
        auto value=kb31_t::load(reinterpret_cast<const kb31_t*>(base),i);uint32_t cube;
        kb31_t::store(reinterpret_cast<kb31_t*>(&cube),0,value*value*value);
        if(cube!=base[count+i])atomicOr(invalid,4u);
    }
}
}
extern "C" void* cmfd_resident_trace_layout_kernel(){return (void*)cmfd_v4_resident::traceLayout;}
extern "C" void* cmfd_resident_validate_words_kernel(){return (void*)cmfd_v4_resident::validateWords;}
extern "C" void* cmfd_resident_derive_activations_kernel(){return (void*)cmfd_v4_resident::deriveActivations;}
extern "C" void* cmfd_resident_validate_lifts_kernel(){return (void*)cmfd_v4_resident::validateLifts;}

// Shift reduced activations and construct equality inputs without a host copy.
__global__ void cmfdRelationInputs(const ext_t* next,const ext_t* boundary,
    const ext_t* layer,ext_t* input,ext_t* equality,size_t count,size_t width) {
    const size_t i=size_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i>=count)return;
    ext_t::store(input,i,i<width?ext_t::load(boundary,i):ext_t::load(next,i-width));
    ext_t::store(equality,i,ext_t::load(layer,i/width));
}
extern "C" void* cmfd_relation_inputs_kernel(){return (void*)cmfdRelationInputs;}
