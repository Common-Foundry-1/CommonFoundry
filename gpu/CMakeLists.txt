cmake_minimum_required(VERSION 3.22)
project(cmfd_forgematrix_gpu LANGUAGES CXX)

option(CMFD_ENABLE_CUDA "Build the NVIDIA CUDA targets" ON)
option(CMFD_ENABLE_OPENCL "Build the OpenCL miner backend (Intel Arc and other GPUs)" ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(CMFD_ENABLE_CUDA)
  enable_language(CUDA)
  set(CMAKE_CUDA_STANDARD 17)
  set(CMAKE_CUDA_STANDARD_REQUIRED ON)

  add_executable(cmfd-forgematrix-cuda forgematrix_cuda.cu)
  add_executable(cmfd-forgematrix-v2-cuda forgematrix_v2_cuda.cu)
  add_library(cmfd-forgematrix-v2-miner SHARED forgematrix_v2_miner.cu)
  target_compile_options(cmfd-forgematrix-cuda PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:--fmad=false>
  )
  target_compile_options(cmfd-forgematrix-v2-cuda PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:--fmad=false>
  )
  target_compile_options(cmfd-forgematrix-v2-miner PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:--fmad=false>
  )
  set_target_properties(cmfd-forgematrix-cuda PROPERTIES
    CUDA_ARCHITECTURES "89;120"
  )
  set_target_properties(cmfd-forgematrix-v2-cuda PROPERTIES
    CUDA_ARCHITECTURES "89;120"
  )
  set_target_properties(cmfd-forgematrix-v2-miner PROPERTIES
    CUDA_ARCHITECTURES "70-real;75-real;86-real;89-real;120-real;70-virtual"
    CUDA_RUNTIME_LIBRARY Static
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    OUTPUT_NAME "cmfd-forgematrix-v2-miner"
    PREFIX ""
  )
endif()

if(CMFD_ENABLE_OPENCL)
  # The OpenCL ICD is resolved at run time, so no OpenCL SDK is needed here.
  add_library(cmfd-forgematrix-v2-opencl SHARED forgematrix_v2_opencl.cpp)
  set_target_properties(cmfd-forgematrix-v2-opencl PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    OUTPUT_NAME "cmfd-forgematrix-v2-opencl"
    PREFIX ""
    CXX_VISIBILITY_PRESET hidden
  )
  if(UNIX)
    target_link_libraries(cmfd-forgematrix-v2-opencl PRIVATE ${CMAKE_DL_LIBS})
  endif()
endif()
