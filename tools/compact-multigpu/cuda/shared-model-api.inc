namespace {
std::unique_ptr<cmfd_v4_replay::ProductionModel> resident_replay_model;
template<class F> int resident_api(F&& fn,char* error,size_t capacity){
    try{fn();cudaError_t status=cudaDeviceSynchronize();if(status!=cudaSuccess)throw std::runtime_error(cudaGetErrorString(status));return 0;}
    catch(const std::exception& problem){if(capacity)std::snprintf(error,capacity,"%s",problem.what());return -1;}
}
}
extern "C" int cmfd_shared_model_open(const uint8_t* b0,const uint8_t* b1,const uint8_t* b2,const uint8_t* base,const uint8_t* first,char* error,size_t capacity){
    return resident_api([&]{
        if(resident_replay_model)throw std::runtime_error("shared model already open");
        char name[]="resident-replay",mode[]="--shared-init";char* args[]={name,mode};
        if(cmfd_resident_replay_main(2,args))throw std::runtime_error("shared replay backend differential failed");
        const uint8_t* banks[]={b0,b1,b2};
        resident_replay_model=std::make_unique<cmfd_v4_replay::ProductionModel>(cmfd_v4_replay::BorrowedModelTag{},banks,base,first);
        cmfd_v4_replay::run_fused_self_check(*resident_replay_model);
    },error,capacity);
}
extern "C" int cmfd_shared_model_run(const char* mode,const char* coefficients,const char* prefix,char* error,size_t capacity){
    return resident_api([&]{
        if(!resident_replay_model)throw std::runtime_error("shared model is not ready");
        bool full=std::string(mode)=="full";
        if(!full&&std::string(mode)!="search")throw std::runtime_error("shared replay mode");
        if(full)cmfd_v4_replay::resident_search_buffers().clear();
        cmfd_v4_replay::run_production_replay(*resident_replay_model,coefficients,prefix,full);
        std::fprintf(stderr,"resident_model_reused=EXACT reload_bytes=0\n");
    },error,capacity);
}
extern "C" int cmfd_shared_model_run_batch(uint32_t count,const char* coefficients,const char* prefix,const char* challenges,char* error,size_t capacity){
    return resident_api([&]{if(!resident_replay_model||count<1||count>64)throw std::runtime_error("shared batch shape");cmfd_v4_replay::run_production_search_batch(*resident_replay_model,count,coefficients,prefix,challenges);},error,capacity);
}
extern "C" int cmfd_shared_model_trim(char* error,size_t capacity){return resident_api([&]{if(!resident_replay_model)throw std::runtime_error("shared model not ready");cmfd_v4_replay::resident_search_buffers().clear();resident_replay_model->evict();},error,capacity);}
extern "C" void cmfd_shared_model_close(){cmfd_v4_replay::resident_search_buffers().clear();resident_replay_model.reset();cudaDeviceSynchronize();}
