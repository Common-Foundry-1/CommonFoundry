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
