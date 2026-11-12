# CUDA 12.9/CMake 4 keep the legacy backend's optional profiling target usable.
if(NOT TARGET CUDA::nvToolsExt)
  add_library(CUDA::nvToolsExt SHARED IMPORTED GLOBAL)
  set_target_properties(CUDA::nvToolsExt PROPERTIES
    IMPORTED_LOCATION "/usr/lib/x86_64-linux-gnu/libnvToolsExt.so.1")
endif()
