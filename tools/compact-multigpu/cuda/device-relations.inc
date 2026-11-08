// Shift reduced activations and construct equality inputs without a host copy.
__global__ void cmfdRelationInputs(const ext_t* next,const ext_t* boundary,
    const ext_t* layer,ext_t* input,ext_t* equality,size_t count,size_t width) {
    const size_t i=size_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i>=count)return;
    ext_t::store(input,i,i<width?ext_t::load(boundary,i):ext_t::load(next,i-width));
    ext_t::store(equality,i,ext_t::load(layer,i/width));
}
extern "C" void* cmfd_relation_inputs_kernel(){return (void*)cmfdRelationInputs;}
