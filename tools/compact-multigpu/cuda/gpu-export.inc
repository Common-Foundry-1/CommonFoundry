bool gpu_witness_enabled() {
    const char* value=std::getenv("CMFD_REPLAY_GPU_IPC");
    return value && std::string(value)=="1";
}
void gpu_witness_memory(const char* phase) {
    if(!gpu_witness_enabled())return;
    size_t free=0,total=0;cuda_check(cudaMemGetInfo(&free,&total),"read replay memory");
    std::fprintf(stderr,"gpu_witness_memory phase=%s total_used_bytes=%zu\n",phase,total-free);
}
class GpuReplayExport {
    uint32_t* pre_=nullptr;
    uint32_t* act_=nullptr;
    std::string prefix_;
    std::atomic<bool> stop_{false};
    std::thread watcher_;
    static std::string hex(const void* data,size_t bytes) {
        static const char* digits="0123456789abcdef";
        const auto* values=static_cast<const uint8_t*>(data);std::string result;result.reserve(bytes*2);
        for(size_t i=0;i<bytes;++i){result+=digits[values[i]>>4];result+=digits[values[i]&15];}return result;
    }
    static void write_owned(const std::string& path,const std::string& text) {
        const std::string pending=path+".pending";
        int fd=::open(pending.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
        if(fd<0)throw std::runtime_error("create private GPU witness metadata");
        size_t done=0;
        while(done<text.size()){
            ssize_t bytes=::write(fd,text.data()+done,text.size()-done);
            if(bytes<=0){::close(fd);throw std::runtime_error("write GPU witness metadata");}done+=size_t(bytes);
        }
        ::close(fd);
        if(::link(pending.c_str(),path.c_str())!=0){::unlink(pending.c_str());throw std::runtime_error("publish GPU witness metadata");}
        ::unlink(pending.c_str());
    }
    bool copied() const {
        const std::string path=prefix_+"-gpu-witness.copied";struct stat info{};
        if(::lstat(path.c_str(),&info)!=0)return false;
        if(!S_ISREG(info.st_mode)||info.st_uid!=::geteuid()||(info.st_mode&077)||info.st_size!=7)
            throw std::runtime_error("invalid private GPU witness acknowledgement");
        int fd=::open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
        if(fd<0)return false;char bytes[8]{};ssize_t count=::read(fd,bytes,8);::close(fd);
        return count==7&&std::string(bytes,7)=="copied\n";
    }
    void release_values() {
        if(pre_){cuda_check(cudaFree(pre_),"release exported preactivation");pre_=nullptr;}
        if(act_){cuda_check(cudaFree(act_),"release exported activation");act_=nullptr;}
    }
public:
    ~GpuReplayExport(){try{clear();}catch(...) {}}
    void clear() {
        stop_.store(true);
        if(watcher_.joinable())watcher_.join();
        release_values();
        if(!prefix_.empty()) {
            for(const char* suffix:{"-gpu-witness.json","-gpu-witness.copied","-gpu-witness.released"}){
                std::error_code ignored;std::filesystem::remove(prefix_+suffix,ignored);
                std::filesystem::remove(prefix_+suffix+".pending",ignored);
            }
        }
        prefix_.clear();
    }
    bool retain(const char* prefix,uint32_t* pre,uint32_t* act,size_t cells,const std::vector<uint32_t>& coefficients) {
        clear();
        struct stat info{};auto parent=std::filesystem::path(prefix).parent_path();
        if(::stat(parent.c_str(),&info)!=0||!S_ISDIR(info.st_mode)||info.st_uid!=::geteuid()||(info.st_mode&077))
            throw std::runtime_error("GPU witness requires an owned private directory");
        cudaIpcMemHandle_t pre_handle{},act_handle{};
        auto first=cudaIpcGetMemHandle(&pre_handle,pre);
        auto second=first==cudaSuccess && act?cudaIpcGetMemHandle(&act_handle,act):first;
        if(first!=cudaSuccess||second!=cudaSuccess){cudaGetLastError();throw std::runtime_error("GPU witness IPC export unavailable");}
        cudaDeviceProp device{};cuda_check(cudaGetDeviceProperties(&device,0),"read GPU witness identity");
        std::string raw_uuid=hex(device.uuid.bytes,16);
        std::string uuid="GPU-"+raw_uuid.substr(0,8)+"-"+raw_uuid.substr(8,4)+"-"+raw_uuid.substr(12,4)+"-"+raw_uuid.substr(16,4)+"-"+raw_uuid.substr(20,12);
        std::vector<uint8_t> mask;mask.reserve(coefficients.size());
        for(uint32_t value:coefficients){if(value>250)throw std::runtime_error("GPU witness coefficient range");mask.push_back(static_cast<uint8_t>(value));}
        std::ostringstream json;
        json<<"{\"schema\":\""<<(act?"CMFD_GPU_WITNESS_V1":"CMFD_GPU_WITNESS_V2")<<"\",\"pid\":"<<::getpid()
            <<",\"gpu_uuid\":\""<<uuid<<"\",\"pre_handle\":\""<<hex(&pre_handle,sizeof(pre_handle))
            <<"\",\"act_handle\":\""<<(act?hex(&act_handle,sizeof(act_handle)):"")
            <<"\",\"pre_bytes\":"<<(size_t(PRODUCTION_LAYERS)*cells*4)
            <<",\"act_bytes\":"<<(act?size_t(PRODUCTION_LAYERS+1)*cells*4:0)
            <<",\"coefficients_hex\":\""<<hex(mask.data(),mask.size())<<"\"}\n";
        prefix_=prefix;write_owned(prefix_+"-gpu-witness.json",json.str());pre_=pre;act_=act;stop_.store(false);
        watcher_=std::thread([this]{
            try {
                cuda_check(cudaSetDevice(0),"select exported witness device");
                while(!stop_.load()){
                    if(copied()){
                        release_values();write_owned(prefix_+"-gpu-witness.released","released\n");
                        std::fprintf(stderr,"gpu_witness_released=EXACT\n");return;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }catch(const std::exception& error){std::fprintf(stderr,"GPU witness release: %s\n",error.what());}
        });
        std::printf("gpu_witness_path=%s-gpu-witness.json bytes=%zu encoding=montgomery_u32\n",prefix,size_t(act?2:1)*PRODUCTION_LAYERS*cells*4);
        return true;
    }
};
GpuReplayExport& gpu_replay_export(){static GpuReplayExport value;return value;}
