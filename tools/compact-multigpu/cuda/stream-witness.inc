// Immutable chunk publication lets export and upload overlap on separate GPUs.
bool stream_witness_enabled(){const char* value=std::getenv("CMFD_WITNESS_PIPELINE");return value&&std::string(value)=="1";}
class ResidentStreamExports {
    std::vector<std::pair<int,std::string>> records_;
public:
    ~ResidentStreamExports(){clear();}
    void clear(){
        for(const auto& record:records_){
            const std::string target="/proc/"+std::to_string(::getpid())+"/fd/"+std::to_string(record.first);
            std::error_code ignored;
            if(std::filesystem::is_symlink(record.second,ignored)&&std::filesystem::read_symlink(record.second,ignored)==target)std::filesystem::remove(record.second,ignored);
            ::close(record.first);
        }
        records_.clear();
    }
    void publish(const std::string& path,const uint8_t* bytes,size_t count){
        int fd=static_cast<int>(::syscall(SYS_memfd_create,"cmfd-witness-chunk",MFD_CLOEXEC|MFD_ALLOW_SEALING));
        if(fd<0)throw std::runtime_error("create immutable witness chunk");
        try {
            size_t done=0;
            while(done<count){ssize_t n=::write(fd,bytes+done,count-done);if(n<0&&errno==EINTR)continue;if(n<=0)throw std::runtime_error("write witness chunk");done+=size_t(n);}
            constexpr int seals=F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL;
            if(::fcntl(fd,F_ADD_SEALS,seals)!=0||(::fcntl(fd,F_GET_SEALS)&seals)!=seals)throw std::runtime_error("seal witness chunk");
            const std::string target="/proc/"+std::to_string(::getpid())+"/fd/"+std::to_string(fd);
            if(::symlink(target.c_str(),path.c_str())!=0)throw std::runtime_error("publish witness chunk");
            records_.emplace_back(fd,path);
        }catch(...){::close(fd);throw;}
    }
};
ResidentStreamExports& resident_stream_exports(){static ResidentStreamExports value;return value;}
void write_stream_witness(const char* prefix,const uint32_t* pre,const std::vector<uint32_t>& coefficients,size_t cells){
    constexpr size_t chunk_bytes=size_t{16}<<20;
    const size_t bank_values=size_t(128)*cells;
    if(bank_values*4%chunk_bytes)throw std::runtime_error("stream witness geometry");
    static const char* digits="0123456789abcdef";std::string hex;
    for(uint32_t value:coefficients){if(value>250)throw std::runtime_error("stream coefficient range");hex+=digits[value>>4];hex+=digits[value&15];}
    const std::string descriptor=std::string(prefix)+"-stream-witness.json",pending=descriptor+".pending";
    const std::string text="{\"schema\":\"CMFD_SEALED_WITNESS_STREAM_V1\",\"provider_pid\":"+std::to_string(::getpid())+",\"chunk_bytes\":"+std::to_string(chunk_bytes)+",\"bank_bytes\":"+std::to_string(bank_values*4)+",\"coefficients_hex\":\""+hex+"\"}\n";
    int fd=::open(pending.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)throw std::runtime_error("create stream witness descriptor");
    size_t done=0;
    while(done<text.size()){ssize_t n=::write(fd,text.data()+done,text.size()-done);if(n<0&&errno==EINTR)continue;if(n<=0){::close(fd);throw std::runtime_error("write stream witness descriptor");}done+=size_t(n);}
    ::close(fd);
    if(::link(pending.c_str(),descriptor.c_str())!=0){::unlink(pending.c_str());throw std::runtime_error("publish stream descriptor");}::unlink(pending.c_str());
    static thread_local ReplayExportStaging staging;
    for(unsigned bank=0;bank<3;++bank){
        for(size_t index=0;index<bank_values*4/chunk_bytes;++index){
            const size_t offset=size_t(bank)*bank_values+index*(chunk_bytes/4);
            cuda_check(cudaMemcpy(staging.data(),pre+offset,chunk_bytes,cudaMemcpyDeviceToHost),"export sealed witness chunk");
            resident_stream_exports().publish(std::string(prefix)+"-bank"+std::to_string(bank)+"-pre-chunk"+std::to_string(index)+".bin",reinterpret_cast<uint8_t*>(staging.data()),chunk_bytes);
        }
    }
    std::fprintf(stderr,"sealed_witness_stream chunks=48 bytes=%zu\n",size_t(3)*bank_values*4);
}
