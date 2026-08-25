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

  set(CMFD_PROOF_CUDA_ARCHITECTURES
    "70-real;75-real;86-real;89-real;120-real;70-virtual"
    CACHE STRING
    "CUDA architectures for the optional Goldilocks proof-acceleration targets"
  )

  add_executable(cmfd-forgematrix-cuda forgematrix_cuda.cu)
  add_executable(cmfd-forgematrix-v2-cuda forgematrix_v2_cuda.cu)
  add_executable(cmfd-proof-goldilocks-canary proof_goldilocks.cu)
  add_executable(cmfd-proof-poseidon2-canary proof_poseidon2.cu)
  add_library(cmfd-proof-goldilocks SHARED
    proof_goldilocks.cu
    proof_poseidon2.cu
  )
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
  target_compile_options(cmfd-proof-goldilocks-canary PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:--fmad=false>
  )
  target_compile_options(cmfd-proof-poseidon2-canary PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:--fmad=false>
  )
  target_compile_options(cmfd-proof-goldilocks PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:--fmad=false>
    $<$<COMPILE_LANGUAGE:CUDA>:--diag-suppress=177>
  )
  target_compile_definitions(cmfd-proof-goldilocks PRIVATE
    CMFD_PROOF_BACKEND_LIBRARY=1
    CMFD_POSEIDON2_BACKEND_LIBRARY=1
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
  set_target_properties(cmfd-proof-goldilocks-canary PROPERTIES
    CUDA_ARCHITECTURES "${CMFD_PROOF_CUDA_ARCHITECTURES}"
    CUDA_RUNTIME_LIBRARY Static
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )
  set_target_properties(cmfd-proof-poseidon2-canary PROPERTIES
    CUDA_ARCHITECTURES "${CMFD_PROOF_CUDA_ARCHITECTURES}"
    CUDA_RUNTIME_LIBRARY Static
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )
  set_target_properties(cmfd-proof-goldilocks PROPERTIES
    CUDA_ARCHITECTURES "${CMFD_PROOF_CUDA_ARCHITECTURES}"
    CUDA_RUNTIME_LIBRARY Static
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    OUTPUT_NAME "cmfd-proof-goldilocks"
    PREFIX ""
    CXX_VISIBILITY_PRESET hidden
    CUDA_VISIBILITY_PRESET hidden
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
