struct BorrowedModelTag {};
struct ResidentSearchBuffers {
    uint32_t capacity=0;int8_t* limbs=nullptr;int8_t* limbs_next=nullptr;
    int32_t* limb_accumulators=nullptr;uint32_t* activations=nullptr;uint32_t* device_coefficients=nullptr;bool allocated_for_fused=false;
    void clear(){cudaDeviceSynchronize();cudaFree(limbs);cudaFree(limbs_next);cudaFree(limb_accumulators);cudaFree(activations);cudaFree(device_coefficients);capacity=0;limbs=limbs_next=nullptr;limb_accumulators=nullptr;activations=device_coefficients=nullptr;}
};
ResidentSearchBuffers& resident_search_buffers(){static ResidentSearchBuffers buffers;return buffers;}
__global__ void resident_encoded_row_sums(const uint8_t* encoded,int32_t* sums,uint32_t layers,uint32_t width) {
    for(size_t index=size_t(blockIdx.x)*blockDim.x+threadIdx.x;index<size_t(layers)*width;index+=size_t(gridDim.x)*blockDim.x){
        const size_t layer=index/width,column=index%width;int32_t sum=0;
        for(size_t common=0;common<width;++common)sum+=decode_model_byte(encoded[layer*width*width+common*width+column]);
        sums[index]=sum;
    }
}
bool host_pre_only_enabled(){const char* value=std::getenv("CMFD_SHARED_MODEL");return value&&std::string(value)=="1";}
void write_host_pre_only(const char* prefix,const uint32_t* pre,const std::vector<uint32_t>& coefficients,size_t cells) {
    const auto parent=std::filesystem::path(prefix).parent_path();struct stat info{};
    if(::lstat(parent.c_str(),&info)!=0||!S_ISDIR(info.st_mode)||info.st_uid!=::geteuid()||(info.st_mode&077))
        throw std::runtime_error("resident witness requires owned private scratch");
    if(stream_witness_enabled()){write_stream_witness(prefix,pre,coefficients,cells);return;}
    for(unsigned bank=0;bank<3;++bank){
        const std::string path=std::string(prefix)+"-bank"+std::to_string(bank)+"-pre.bin";
        int fd=::open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if(fd<0)throw std::runtime_error("create resident preactivation witness");
        static thread_local ReplayExportStaging staging;
        const size_t values=size_t(128)*cells;
        try {
            for(size_t at=0;at<values;at+=ReplayExportStaging::VALUES){
                size_t count=std::min(ReplayExportStaging::VALUES,values-at);
                cuda_check(cudaMemcpy(staging.data(),pre+size_t(bank)*values+at,count*4,cudaMemcpyDeviceToHost),"export resident preactivation chunk");
                size_t done=0;
                while(done<count*4){ssize_t wrote=::write(fd,reinterpret_cast<char*>(staging.data())+done,count*4-done);if(wrote<0&&errno==EINTR)continue;if(wrote<=0)throw std::runtime_error("write resident witness");done+=size_t(wrote);}
            }
        }catch(...){::close(fd);throw;}
        ::close(fd);
    }
    static const char* hex="0123456789abcdef";std::string encoded;
    for(uint32_t v:coefficients){if(v>250)throw std::runtime_error("resident coefficient range");encoded+=hex[v>>4];encoded+=hex[v&15];}
    const std::string text="{\"schema\":\"CMFD_HOST_PRE_ONLY_V1\",\"coefficients_hex\":\""+encoded+"\"}\n";
    const std::string path=std::string(prefix)+"-host-pre-only.json";
    int fd=::open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)throw std::runtime_error("create resident witness descriptor");
    size_t done=0;while(done<text.size()){ssize_t n=::write(fd,text.data()+done,text.size()-done);if(n<=0){::close(fd);throw std::runtime_error("write resident witness descriptor");}done+=size_t(n);}::close(fd);
}
