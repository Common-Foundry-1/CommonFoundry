    ProductionModel(BorrowedModelTag,const uint8_t* const banks[3],const uint8_t* encoded_base,const uint8_t* first_layer)
        :model_path_("shared-resident"),borrowed_model_(true) {
        for(unsigned i=0;i<3;++i)borrowed_banks_[i]=banks[i];
        size_t total=0;cuda_check(cudaMemGetInfo(&baseline_free_,&total),"read shared model baseline");
        host_base_.resize(MODEL_BASE_BYTES);
        std::transform(encoded_base,encoded_base+MODEL_BASE_BYTES,host_base_.begin(),decode_model_byte);
        first_canonical_layer_.resize(size_t(PRODUCTION_WIDTH)*PRODUCTION_WIDTH);
        std::transform(first_layer,first_layer+first_canonical_layer_.size(),first_canonical_layer_.begin(),decode_model_byte);
        cuda_check(cudaMalloc(&device_base_,MODEL_BASE_BYTES),"allocate shared base");
        cuda_check(cudaMemcpy(device_base_,host_base_.data(),MODEL_BASE_BYTES,cudaMemcpyHostToDevice),"upload shared base");
        cuda_check(cudaMalloc(&device_weight_row_sums_,size_t(PRODUCTION_LAYERS)*PRODUCTION_WIDTH*4),"allocate shared row sums");
        for(unsigned bank=0;bank<3;++bank)resident_encoded_row_sums<<<512,256>>>(borrowed_banks_[bank],device_weight_row_sums_+size_t(bank)*128*PRODUCTION_WIDTH,128,PRODUCTION_WIDTH);
        cuda_check(cudaDeviceSynchronize(),"prepare exact shared row sums");
        std::fprintf(stderr,"resident_model_open copies=0 resident_weight_bytes=%zu\n",size_t(3)*128*PRODUCTION_WIDTH*PRODUCTION_WIDTH);
    }
    const int8_t* layer_weights(uint32_t layer) {
        if(!borrowed_model_)return weights_+size_t(layer)*PRODUCTION_WIDTH*PRODUCTION_WIDTH;
        if(layer>=PRODUCTION_LAYERS)throw std::runtime_error("shared layer range");
        if(!weights_)cuda_check(cudaMalloc(&weights_,size_t(PRODUCTION_WIDTH)*PRODUCTION_WIDTH),"allocate single shared decode layer");
        const uint8_t* encoded=borrowed_banks_[layer/128]+size_t(layer%128)*PRODUCTION_WIDTH*PRODUCTION_WIDTH;
        decode_transpose_square_layer<<<dim3(PRODUCTION_WIDTH/32,PRODUCTION_WIDTH/32),dim3(32,8)>>>(encoded,weights_,PRODUCTION_WIDTH);
        cuda_check(cudaGetLastError(),"decode resident layer without host transfer");
        return weights_;
    }
