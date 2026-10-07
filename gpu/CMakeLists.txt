cmake_minimum_required(VERSION 3.22)
project(cmfd_forgematrix_gpu LANGUAGES CXX)

option(CMFD_ENABLE_CUDA "Build the NVIDIA CUDA targets" ON)
option(CMFD_ENABLE_OPENCL "Build the OpenCL miner backend (Intel Arc and other GPUs)" ON)
set(CMFD_CUTLASS_ROOT "" CACHE PATH "Path to the pinned CUTLASS v3.9.2 checkout")
set(CMFD_CUTLASS_COMMIT
  "ad7b2f5e84fcfa124cb02b91d5bd26d238c0459e"
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(CMFD_ENABLE_CUDA)
  enable_language(CUDA)
  set(CMAKE_CUDA_STANDARD 17)
  set(CMAKE_CUDA_STANDARD_REQUIRED ON)

  set(CMFD_PROOF_CUDA_ARCHITECTURES
    "86-real;89-real"
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
  set(CMFD_FORGEMATRIX_V2_MINER_SOURCES forgematrix_v2_miner.cu)
  if(CMFD_CUTLASS_ROOT)
    if(NOT EXISTS "${CMFD_CUTLASS_ROOT}/include/cutlass/cutlass.h")
      message(FATAL_ERROR "CMFD_CUTLASS_ROOT does not contain CUTLASS headers")
    endif()
    find_package(Git REQUIRED)
    execute_process(
      COMMAND "${GIT_EXECUTABLE}" -C "${CMFD_CUTLASS_ROOT}" rev-parse HEAD
      RESULT_VARIABLE CMFD_CUTLASS_REVISION_RESULT
      OUTPUT_VARIABLE CMFD_CUTLASS_REVISION
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET
    )
    if(NOT CMFD_CUTLASS_REVISION_RESULT EQUAL 0 OR
       NOT CMFD_CUTLASS_REVISION STREQUAL CMFD_CUTLASS_COMMIT)
      message(FATAL_ERROR
        "CUTLASS must be the pinned commit ${CMFD_CUTLASS_COMMIT}; got ${CMFD_CUTLASS_REVISION}"
      )
    endif()
    execute_process(
      COMMAND "${GIT_EXECUTABLE}" -C "${CMFD_CUTLASS_ROOT}"
        status --porcelain --untracked-files=all
      RESULT_VARIABLE CMFD_CUTLASS_STATUS_RESULT
      OUTPUT_VARIABLE CMFD_CUTLASS_STATUS
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET
    )
    if(NOT CMFD_CUTLASS_STATUS_RESULT EQUAL 0 OR CMFD_CUTLASS_STATUS)
      message(FATAL_ERROR "The pinned CUTLASS checkout must be clean")
    endif()
    add_library(cmfd-forgematrix-v2-tensor-core OBJECT
      forgematrix_v2_tensor_core.cu
    )
    target_include_directories(cmfd-forgematrix-v2-tensor-core PRIVATE
      "${CMFD_CUTLASS_ROOT}/include"
    )
    target_compile_options(cmfd-forgematrix-v2-tensor-core PRIVATE
      $<$<COMPILE_LANGUAGE:CUDA>:--fmad=false>
      $<$<COMPILE_LANGUAGE:CUDA>:-diag-suppress=20013>
      $<$<COMPILE_LANGUAGE:CUDA>:-diag-suppress=20015>
      $<$<AND:$<COMPILE_LANGUAGE:CUDA>,$<CXX_COMPILER_ID:MSVC>>:-Xcompiler=/Zc:__cplusplus>
    )
    set_target_properties(cmfd-forgematrix-v2-tensor-core PROPERTIES
      CUDA_ARCHITECTURES "86-real;89-real"
      CUDA_RUNTIME_LIBRARY Static
      MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
      POSITION_INDEPENDENT_CODE ON
    )
    list(APPEND CMFD_FORGEMATRIX_V2_MINER_SOURCES
      $<TARGET_OBJECTS:cmfd-forgematrix-v2-tensor-core>
    )
  endif()
  add_library(cmfd-forgematrix-v2-miner SHARED ${CMFD_FORGEMATRIX_V2_MINER_SOURCES})
  if(CMFD_CUTLASS_ROOT)
    target_compile_definitions(cmfd-forgematrix-v2-miner PRIVATE
      CMFD_CUTLASS_ENABLED=1
    )
  else()
    target_compile_definitions(cmfd-forgematrix-v2-miner PRIVATE
      CMFD_CUTLASS_ENABLED=0
    )
  endif()
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
    CUDA_ARCHITECTURES "89"
  )
  set_target_properties(cmfd-forgematrix-v2-cuda PROPERTIES
    CUDA_ARCHITECTURES "89"
  )
  set_target_properties(cmfd-forgematrix-v2-miner PROPERTIES
    CUDA_ARCHITECTURES "86-real;89-real"
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
