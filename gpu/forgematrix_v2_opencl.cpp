// ForgeMatrix v2 miner backend for OpenCL devices, including Intel Arc.
//
// It exports the same versioned C ABI as the CUDA backend so the Rust loader
// can drive either library. The OpenCL runtime is resolved at load time, so
// this translation unit builds without an OpenCL SDK installed.

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#if defined(_WIN32)
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define CMFD_CUDA_EXPORT extern "C" __declspec(dllexport)
#else
#include <dlfcn.h>
#define CMFD_CUDA_EXPORT extern "C" __attribute__((visibility("default")))
#endif

namespace {

constexpr uint32_t API_VERSION = 1;
constexpr uint32_t MAX_WIDTH = 32;
constexpr uint32_t MAX_ROWS = 4;
constexpr uint32_t MAX_LAYERS = 4;
constexpr uint32_t MAX_BATCH = 65536;
constexpr size_t THREADS = 128;

// Minimal OpenCL 1.2 declarations. The ICD loader owns every definition; this
// file only needs the handful of entry points the batch evaluator calls.
using cl_int = int32_t;
using cl_uint = uint32_t;
using cl_ulong = uint64_t;
using cl_bool = cl_uint;
using cl_bitfield = cl_ulong;
using cl_device_type = cl_bitfield;
using cl_mem_flags = cl_bitfield;
using cl_platform_id = void*;
using cl_device_id = void*;
using cl_context = void*;
using cl_command_queue = void*;
using cl_program = void*;
using cl_kernel = void*;
using cl_mem = void*;
using cl_event = void*;

constexpr cl_int CL_SUCCESS_CODE = 0;
constexpr cl_bool CL_TRUE_VALUE = 1;
constexpr cl_device_type CL_DEVICE_TYPE_GPU_BIT = 1 << 2;
constexpr cl_uint CL_DEVICE_NAME_INFO = 0x102B;
constexpr cl_uint CL_DEVICE_VENDOR_INFO = 0x102C;
constexpr cl_uint CL_DEVICE_VERSION_INFO = 0x102F;
constexpr cl_uint CL_DEVICE_GLOBAL_MEM_SIZE_INFO = 0x101F;
constexpr cl_uint CL_DEVICE_MAX_WORK_GROUP_SIZE_INFO = 0x1004;
constexpr cl_uint CL_PROGRAM_BUILD_LOG_INFO = 0x1183;
constexpr cl_uint CL_PLATFORM_NAME_INFO = 0x0902;
constexpr cl_mem_flags CL_MEM_WRITE_ONLY_FLAG = 1 << 1;
constexpr cl_mem_flags CL_MEM_READ_ONLY_FLAG = 1 << 2;

struct OpenClApi {
    cl_int (*GetPlatformIDs)(cl_uint, cl_platform_id*, cl_uint*) = nullptr;
    cl_int (*GetDeviceIDs)(cl_platform_id, cl_device_type, cl_uint, cl_device_id*, cl_uint*) =
        nullptr;
    cl_int (*GetDeviceInfo)(cl_device_id, cl_uint, size_t, void*, size_t*) = nullptr;
    cl_int (*GetPlatformInfo)(cl_platform_id, cl_uint, size_t, void*, size_t*) = nullptr;
    cl_context (*CreateContext)(const intptr_t*, cl_uint, const cl_device_id*, void*, void*,
                                cl_int*) = nullptr;
    cl_command_queue (*CreateCommandQueue)(cl_context, cl_device_id, cl_bitfield, cl_int*) =
        nullptr;
    cl_command_queue (*CreateCommandQueueWithProperties)(cl_context, cl_device_id, const intptr_t*,
                                                         cl_int*) = nullptr;
    cl_program (*CreateProgramWithSource)(cl_context, cl_uint, const char**, const size_t*,
                                          cl_int*) = nullptr;
    cl_int (*BuildProgram)(cl_program, cl_uint, const cl_device_id*, const char*, void*, void*) =
        nullptr;
    cl_int (*GetProgramBuildInfo)(cl_program, cl_device_id, cl_uint, size_t, void*, size_t*) =
        nullptr;
    cl_kernel (*CreateKernel)(cl_program, const char*, cl_int*) = nullptr;
    cl_mem (*CreateBuffer)(cl_context, cl_mem_flags, size_t, void*, cl_int*) = nullptr;
    cl_int (*EnqueueWriteBuffer)(cl_command_queue, cl_mem, cl_bool, size_t, size_t, const void*,
                                 cl_uint, const cl_event*, cl_event*) = nullptr;
    cl_int (*EnqueueReadBuffer)(cl_command_queue, cl_mem, cl_bool, size_t, size_t, void*, cl_uint,
                                const cl_event*, cl_event*) = nullptr;
    cl_int (*SetKernelArg)(cl_kernel, cl_uint, size_t, const void*) = nullptr;
    cl_int (*EnqueueNDRangeKernel)(cl_command_queue, cl_kernel, cl_uint, const size_t*,
                                   const size_t*, const size_t*, cl_uint, const cl_event*,
                                   cl_event*) = nullptr;
    cl_int (*Finish)(cl_command_queue) = nullptr;
    cl_int (*ReleaseMemObject)(cl_mem) = nullptr;
    cl_int (*ReleaseKernel)(cl_kernel) = nullptr;
    cl_int (*ReleaseProgram)(cl_program) = nullptr;
    cl_int (*ReleaseCommandQueue)(cl_command_queue) = nullptr;
    cl_int (*ReleaseContext)(cl_context) = nullptr;
};

#if defined(_WIN32)
using LibraryHandle = HMODULE;
LibraryHandle open_library(const char* name) { return LoadLibraryA(name); }
void* library_symbol(LibraryHandle handle, const char* name) {
    return reinterpret_cast<void*>(GetProcAddress(handle, name));
}
constexpr const char* LIBRARY_NAMES[] = {"OpenCL.dll"};
#else
using LibraryHandle = void*;
LibraryHandle open_library(const char* name) { return dlopen(name, RTLD_NOW | RTLD_LOCAL); }
void* library_symbol(LibraryHandle handle, const char* name) { return dlsym(handle, name); }
constexpr const char* LIBRARY_NAMES[] = {"libOpenCL.so.1", "libOpenCL.so"};
#endif

template <typename Fn>
void bind_symbol(LibraryHandle handle, const char* name, Fn& slot, bool required) {
    void* symbol = library_symbol(handle, name);
    if (symbol == nullptr) {
        if (required) {
            throw std::runtime_error(std::string("OpenCL runtime is missing ") + name);
        }
        return;
    }
    slot = reinterpret_cast<Fn>(symbol);
}

const OpenClApi& opencl() {
    static OpenClApi* api = [] {
        LibraryHandle handle = nullptr;
        for (const char* name : LIBRARY_NAMES) {
            handle = open_library(name);
            if (handle != nullptr) break;
        }
        if (handle == nullptr) {
            throw std::runtime_error(
                "OpenCL runtime was not found. Install the Intel Arc graphics driver or another "
                "OpenCL ICD.");
        }
        auto* loaded = new OpenClApi();
        bind_symbol(handle, "clGetPlatformIDs", loaded->GetPlatformIDs, true);
        bind_symbol(handle, "clGetDeviceIDs", loaded->GetDeviceIDs, true);
        bind_symbol(handle, "clGetDeviceInfo", loaded->GetDeviceInfo, true);
        bind_symbol(handle, "clGetPlatformInfo", loaded->GetPlatformInfo, true);
        bind_symbol(handle, "clCreateContext", loaded->CreateContext, true);
        bind_symbol(handle, "clCreateCommandQueue", loaded->CreateCommandQueue, false);
        bind_symbol(handle, "clCreateCommandQueueWithProperties",
                    loaded->CreateCommandQueueWithProperties, false);
        bind_symbol(handle, "clCreateProgramWithSource", loaded->CreateProgramWithSource, true);
        bind_symbol(handle, "clBuildProgram", loaded->BuildProgram, true);
        bind_symbol(handle, "clGetProgramBuildInfo", loaded->GetProgramBuildInfo, true);
        bind_symbol(handle, "clCreateKernel", loaded->CreateKernel, true);
        bind_symbol(handle, "clCreateBuffer", loaded->CreateBuffer, true);
        bind_symbol(handle, "clEnqueueWriteBuffer", loaded->EnqueueWriteBuffer, true);
        bind_symbol(handle, "clEnqueueReadBuffer", loaded->EnqueueReadBuffer, true);
        bind_symbol(handle, "clSetKernelArg", loaded->SetKernelArg, true);
        bind_symbol(handle, "clEnqueueNDRangeKernel", loaded->EnqueueNDRangeKernel, true);
        bind_symbol(handle, "clFinish", loaded->Finish, true);
        bind_symbol(handle, "clReleaseMemObject", loaded->ReleaseMemObject, true);
        bind_symbol(handle, "clReleaseKernel", loaded->ReleaseKernel, true);
        bind_symbol(handle, "clReleaseProgram", loaded->ReleaseProgram, true);
        bind_symbol(handle, "clReleaseCommandQueue", loaded->ReleaseCommandQueue, true);
        bind_symbol(handle, "clReleaseContext", loaded->ReleaseContext, true);
        if (loaded->CreateCommandQueue == nullptr &&
            loaded->CreateCommandQueueWithProperties == nullptr) {
            throw std::runtime_error("OpenCL runtime exposes no command queue constructor");
        }
        return loaded;
    }();
    return *api;
}

void cl_check(cl_int result, const char* operation) {
    if (result != CL_SUCCESS_CODE) {
        throw std::runtime_error(std::string(operation) + ": OpenCL error " +
                                 std::to_string(result));
    }
}

void write_error(char* output, size_t output_len, const std::string& message) {
    if (output == nullptr || output_len == 0) return;
    const size_t copied = std::min(output_len - 1, message.size());
    std::memcpy(output, message.data(), copied);
    output[copied] = '\0';
}

uint32_t exact_log2(uint32_t value) {
    if (value == 0 || (value & (value - 1)) != 0) {
        throw std::runtime_error("dimensions must be powers of two");
    }
    uint32_t bits = 0;
    while ((uint32_t{1} << bits) != value) ++bits;
    return bits;
}

void validate_canonical(const uint8_t* values, size_t length, const char* label) {
    if (values == nullptr) throw std::runtime_error(std::string(label) + " is null");
    for (size_t index = 0; index < length; ++index) {
        if (values[index] > 250) {
            throw std::runtime_error(std::string(label) + " contains a noncanonical byte");
        }
    }
}

std::string platform_string(cl_platform_id platform, cl_uint parameter) {
    size_t length = 0;
    if (opencl().GetPlatformInfo(platform, parameter, 0, nullptr, &length) != CL_SUCCESS_CODE ||
        length == 0) {
        return {};
    }
    std::string value(length, '\0');
    if (opencl().GetPlatformInfo(platform, parameter, length, value.data(), nullptr) !=
        CL_SUCCESS_CODE) {
        return {};
    }
    while (!value.empty() && value.back() == '\0') value.pop_back();
    return value;
}

// Translation layers such as Microsoft OpenCLOn12 re-expose a card that its
// native driver already offers, which would double count one GPU and mine it
// through D3D12. They are skipped unless CMFD_OPENCL_ALL_PLATFORMS is set.
bool platform_is_translation_layer(cl_platform_id platform) {
    const char* allow_all = std::getenv("CMFD_OPENCL_ALL_PLATFORMS");
    if (allow_all != nullptr && allow_all[0] != '\0' && std::strcmp(allow_all, "0") != 0) {
        return false;
    }
    std::string name = platform_string(platform, CL_PLATFORM_NAME_INFO);
    std::transform(name.begin(), name.end(), name.begin(),
                   [](unsigned char letter) { return static_cast<char>(std::tolower(letter)); });
    return name.find("openclon12") != std::string::npos ||
           name.find("clon12") != std::string::npos;
}

std::string device_string(cl_device_id device, cl_uint parameter) {
    size_t length = 0;
    cl_check(opencl().GetDeviceInfo(device, parameter, 0, nullptr, &length), "read device text");
    std::string value(length, '\0');
    cl_check(opencl().GetDeviceInfo(device, parameter, length, value.data(), nullptr),
             "read device text");
    while (!value.empty() && value.back() == '\0') value.pop_back();
    return value;
}

// Every OpenCL GPU across every platform, in a stable enumeration order so a
// device index keeps naming the same card between runs.
std::vector<cl_device_id> enumerate_devices() {
    cl_uint platform_count = 0;
    if (opencl().GetPlatformIDs(0, nullptr, &platform_count) != CL_SUCCESS_CODE ||
        platform_count == 0) {
        return {};
    }
    std::vector<cl_platform_id> platforms(platform_count);
    cl_check(opencl().GetPlatformIDs(platform_count, platforms.data(), nullptr),
             "enumerate OpenCL platforms");

    std::vector<cl_device_id> devices;
    for (cl_platform_id platform : platforms) {
        if (platform_is_translation_layer(platform)) continue;
        cl_uint device_count = 0;
        if (opencl().GetDeviceIDs(platform, CL_DEVICE_TYPE_GPU_BIT, 0, nullptr, &device_count) !=
                CL_SUCCESS_CODE ||
            device_count == 0) {
            continue;
        }
        std::vector<cl_device_id> platform_devices(device_count);
        if (opencl().GetDeviceIDs(platform, CL_DEVICE_TYPE_GPU_BIT, device_count,
                                  platform_devices.data(), nullptr) != CL_SUCCESS_CODE) {
            continue;
        }
        devices.insert(devices.end(), platform_devices.begin(), platform_devices.end());
    }
    return devices;
}

cl_device_id device_at(int32_t device_index) {
    const std::vector<cl_device_id> devices = enumerate_devices();
    if (device_index < 0 || static_cast<size_t>(device_index) >= devices.size()) {
        throw std::runtime_error("OpenCL device index " + std::to_string(device_index) +
                                 " is outside the available range 0.." +
                                 std::to_string(devices.size()));
    }
    return devices[static_cast<size_t>(device_index)];
}

// CL_DEVICE_VERSION is "OpenCL <major>.<minor> <vendor text>". The loader
// reports the pair as the backend capability version.
void parse_version(const std::string& version, uint32_t& major, uint32_t& minor) {
    major = 0;
    minor = 0;
    const size_t space = version.find(' ');
    if (space == std::string::npos) return;
    const size_t dot = version.find('.', space + 1);
    if (dot == std::string::npos) return;
    try {
        major = static_cast<uint32_t>(std::stoul(version.substr(space + 1, dot - space - 1)));
        minor = static_cast<uint32_t>(std::stoul(version.substr(dot + 1)));
    } catch (const std::exception&) {
        major = 0;
        minor = 0;
    }
}

// One work group per nonce, mirroring the CUDA kernel value for value. Every
// operation is exact integer arithmetic, so both backends and the CPU
// reference agree bit for bit.
constexpr const char* KERNEL_SOURCE = R"CLC(
inline int coordinate_mask(__global const uchar* coefficients, uint row, uint col, uint row_bits,
                           uint col_bits) {
    int mask = (int)coefficients[0];
    for (uint bit = 0; bit < row_bits; ++bit) {
        if (((row >> bit) & 1u) != 0u) mask += (int)coefficients[1 + bit];
    }
    for (uint bit = 0; bit < col_bits; ++bit) {
        if (((col >> bit) & 1u) != 0u) mask += (int)coefficients[1 + row_bits + bit];
    }
    return mask;
}

inline char cubic_reduce(int z) {
    const uint transition_modulus = 134217689u;
    const uint encoded = z >= 0 ? (uint)z : (uint)((long)transition_modulus + (long)z);
    const ulong square = (ulong)encoded * (ulong)encoded;
    const uint square_remainder = (uint)(square % (ulong)transition_modulus);
    const ulong cube_product = (ulong)square_remainder * (ulong)encoded;
    const uint cube_remainder = (uint)(cube_product % (ulong)transition_modulus);
    return (char)((int)(cube_remainder % 251u) - 125);
}

__kernel __attribute__((reqd_work_group_size(128, 1, 1)))
void evaluate_batch(__global const uchar* base, __global const char* transposed_weights,
                    __global const uchar* all_coefficients, __global uchar* outputs, uint rows,
                    uint width, uint layers, uint coefficient_count, uint batch_count) {
    const uint nonce_index = get_group_id(0);
    if (nonce_index >= batch_count) return;

    __local char activation[2][128];
    const uint index = get_local_id(0);
    const uint activation_len = rows * width;
    const uint row_bits = 31u - clz(rows);
    const uint col_bits = 31u - clz(width);
    const uint stages = layers + 1u;
    __global const uchar* nonce_coefficients =
        all_coefficients + (ulong)nonce_index * stages * coefficient_count;

    if (index < activation_len) {
        const uint row = index / width;
        const uint col = index % width;
        const int z = (int)base[index] - 125 +
                      coordinate_mask(nonce_coefficients, row, col, row_bits, col_bits);
        activation[0][index] = cubic_reduce(z);
    }
    barrier(CLK_LOCAL_MEM_FENCE);

    for (uint layer = 0; layer < layers; ++layer) {
        const uint input_bank = layer & 1u;
        const uint output_bank = input_bank ^ 1u;
        if (index < activation_len) {
            const uint row = index / width;
            const uint col = index % width;
            __local const char* input = &activation[input_bank][row * width];
            __global const char* weights =
                transposed_weights + (ulong)layer * width * width + (ulong)col * width;
            int accumulator = 0;
            for (uint common = 0; common < width; ++common) {
                accumulator += (int)input[common] * (int)weights[common];
            }
            __global const uchar* coefficients =
                nonce_coefficients + (ulong)(layer + 1u) * coefficient_count;
            const int z = accumulator + coordinate_mask(coefficients, row, col, row_bits, col_bits);
            activation[output_bank][index] = cubic_reduce(z);
        }
        barrier(CLK_LOCAL_MEM_FENCE);
    }

    if (index < activation_len) {
        outputs[(ulong)nonce_index * activation_len + index] =
            (uchar)((int)activation[layers & 1u][index] + 125);
    }
}
)CLC";

struct Context {
    int32_t device_index = 0;
    cl_device_id device = nullptr;
    cl_context context = nullptr;
    cl_command_queue queue = nullptr;
    cl_program program = nullptr;
    cl_kernel kernel = nullptr;
    uint32_t rows = 0;
    uint32_t width = 0;
    uint32_t layers = 0;
    uint32_t coefficient_count = 0;
    uint32_t activation_len = 0;
    uint32_t capacity = 0;
    cl_mem device_base = nullptr;
    cl_mem device_weights = nullptr;
    cl_mem device_coefficients = nullptr;
    cl_mem device_outputs = nullptr;

    ~Context() {
        const OpenClApi& api = opencl();
        if (device_outputs != nullptr) api.ReleaseMemObject(device_outputs);
        if (device_coefficients != nullptr) api.ReleaseMemObject(device_coefficients);
        if (device_weights != nullptr) api.ReleaseMemObject(device_weights);
        if (device_base != nullptr) api.ReleaseMemObject(device_base);
        if (kernel != nullptr) api.ReleaseKernel(kernel);
        if (program != nullptr) api.ReleaseProgram(program);
        if (queue != nullptr) api.ReleaseCommandQueue(queue);
        if (context != nullptr) api.ReleaseContext(context);
    }
};

cl_mem create_buffer(cl_context context, cl_mem_flags flags, size_t bytes, const char* operation) {
    cl_int status = CL_SUCCESS_CODE;
    cl_mem buffer = opencl().CreateBuffer(context, flags, bytes, nullptr, &status);
    cl_check(status, operation);
    if (buffer == nullptr) throw std::runtime_error(std::string(operation) + ": null buffer");
    return buffer;
}

void ensure_capacity(Context& context, uint32_t count) {
    if (context.capacity >= count) return;
    const OpenClApi& api = opencl();
    if (context.device_outputs != nullptr) api.ReleaseMemObject(context.device_outputs);
    if (context.device_coefficients != nullptr) api.ReleaseMemObject(context.device_coefficients);
    context.device_outputs = nullptr;
    context.device_coefficients = nullptr;
    context.capacity = 0;

    const size_t coefficient_bytes =
        size_t(count) * (context.layers + 1) * context.coefficient_count;
    const size_t output_bytes = size_t(count) * context.activation_len;
    context.device_coefficients = create_buffer(context.context, CL_MEM_READ_ONLY_FLAG,
                                                coefficient_bytes, "allocate batch coefficients");
    try {
        context.device_outputs = create_buffer(context.context, CL_MEM_WRITE_ONLY_FLAG,
                                               output_bytes, "allocate batch outputs");
    } catch (...) {
        api.ReleaseMemObject(context.device_coefficients);
        context.device_coefficients = nullptr;
        throw;
    }
    context.capacity = count;
}

std::string build_log(cl_program program, cl_device_id device) {
    size_t length = 0;
    if (opencl().GetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG_INFO, 0, nullptr,
                                     &length) != CL_SUCCESS_CODE ||
        length == 0) {
        return {};
    }
    std::string log(length, '\0');
    if (opencl().GetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG_INFO, length, log.data(),
                                     nullptr) != CL_SUCCESS_CODE) {
        return {};
    }
    while (!log.empty() && (log.back() == '\0' || log.back() == '\n')) log.pop_back();
    return log;
}

}  // namespace

struct CmfdCudaDeviceInfo {
    uint32_t api_version;
    int32_t device_index;
    uint32_t compute_major;
    uint32_t compute_minor;
    uint64_t total_memory_bytes;
    char name[128];
};

CMFD_CUDA_EXPORT uint32_t cmfd_cuda_api_version() { return API_VERSION; }

CMFD_CUDA_EXPORT int32_t cmfd_cuda_device_count(int32_t* count, char* error, size_t error_len) {
    try {
        if (count == nullptr) throw std::runtime_error("device count output is null");
        *count = static_cast<int32_t>(enumerate_devices().size());
        return 0;
    } catch (const std::exception& exception) {
        write_error(error, error_len, exception.what());
        return 1;
    }
}

CMFD_CUDA_EXPORT int32_t cmfd_cuda_device_info(int32_t device_index, CmfdCudaDeviceInfo* output,
                                               char* error, size_t error_len) {
    try {
        if (output == nullptr) throw std::runtime_error("device info output is null");
        cl_device_id device = device_at(device_index);
        std::memset(output, 0, sizeof(*output));
        output->api_version = API_VERSION;
        output->device_index = device_index;
        uint32_t major = 0;
        uint32_t minor = 0;
        parse_version(device_string(device, CL_DEVICE_VERSION_INFO), major, minor);
        output->compute_major = major;
        output->compute_minor = minor;
        cl_ulong memory = 0;
        cl_check(opencl().GetDeviceInfo(device, CL_DEVICE_GLOBAL_MEM_SIZE_INFO, sizeof(memory),
                                        &memory, nullptr),
                 "read device memory");
        output->total_memory_bytes = static_cast<uint64_t>(memory);

        std::string name = device_string(device, CL_DEVICE_NAME_INFO);
        if (name.empty()) name = device_string(device, CL_DEVICE_VENDOR_INFO);
        std::strncpy(output->name, name.c_str(), sizeof(output->name) - 1);
        return 0;
    } catch (const std::exception& exception) {
        write_error(error, error_len, exception.what());
        return 1;
    }
}

CMFD_CUDA_EXPORT int32_t cmfd_cuda_create(int32_t device_index, uint32_t rows, uint32_t width,
                                          uint32_t layers, uint32_t coefficient_count,
                                          const uint8_t* base_input, size_t base_input_len,
                                          const uint8_t* weights, size_t weights_len,
                                          void** output_context, char* error, size_t error_len) {
    try {
        if (output_context == nullptr) throw std::runtime_error("context output is null");
        *output_context = nullptr;
        if (rows == 0 || rows > MAX_ROWS || width == 0 || width > MAX_WIDTH || layers == 0 ||
            layers > MAX_LAYERS) {
            throw std::runtime_error("OpenCL backend accepts only the bounded v2 research profile");
        }
        const uint32_t row_bits = exact_log2(rows);
        const uint32_t col_bits = exact_log2(width);
        if (coefficient_count != 1 + row_bits + col_bits) {
            throw std::runtime_error("coefficient count mismatch");
        }
        const size_t activation_len = size_t(rows) * width;
        const size_t expected_weights = size_t(layers) * width * width;
        if (base_input_len != activation_len || weights_len != expected_weights) {
            throw std::runtime_error("model byte length mismatch");
        }
        validate_canonical(base_input, base_input_len, "base input");
        validate_canonical(weights, weights_len, "weights");

        const OpenClApi& api = opencl();
        cl_device_id device = device_at(device_index);
        size_t max_group = 0;
        cl_check(api.GetDeviceInfo(device, CL_DEVICE_MAX_WORK_GROUP_SIZE_INFO, sizeof(max_group),
                                   &max_group, nullptr),
                 "read device work group size");
        if (max_group < THREADS) {
            throw std::runtime_error("OpenCL device supports work groups of only " +
                                     std::to_string(max_group) + "; ForgeMatrix requires 128");
        }

        auto context = std::make_unique<Context>();
        context->device_index = device_index;
        context->device = device;
        context->rows = rows;
        context->width = width;
        context->layers = layers;
        context->coefficient_count = coefficient_count;
        context->activation_len = static_cast<uint32_t>(activation_len);

        cl_int status = CL_SUCCESS_CODE;
        context->context = api.CreateContext(nullptr, 1, &device, nullptr, nullptr, &status);
        cl_check(status, "create OpenCL context");
        if (api.CreateCommandQueueWithProperties != nullptr) {
            const intptr_t properties[] = {0};
            context->queue = api.CreateCommandQueueWithProperties(context->context, device,
                                                                  properties, &status);
        } else {
            context->queue = api.CreateCommandQueue(context->context, device, 0, &status);
        }
        cl_check(status, "create OpenCL command queue");

        const char* sources[] = {KERNEL_SOURCE};
        context->program =
            api.CreateProgramWithSource(context->context, 1, sources, nullptr, &status);
        cl_check(status, "create ForgeMatrix v2 program");
        // No fast-math or reassociating options: the relation must stay exact.
        const cl_int build_status =
            api.BuildProgram(context->program, 1, &device, "-cl-std=CL1.2", nullptr, nullptr);
        if (build_status != CL_SUCCESS_CODE) {
            const std::string log = build_log(context->program, device);
            throw std::runtime_error("ForgeMatrix v2 kernel build failed: " +
                                     (log.empty() ? std::to_string(build_status) : log));
        }
        context->kernel = api.CreateKernel(context->program, "evaluate_batch", &status);
        cl_check(status, "create ForgeMatrix v2 kernel");

        std::vector<int8_t> transposed_weights(expected_weights);
        for (uint32_t layer = 0; layer < layers; ++layer) {
            for (uint32_t col = 0; col < width; ++col) {
                for (uint32_t common = 0; common < width; ++common) {
                    const size_t source =
                        size_t(layer) * width * width + size_t(common) * width + col;
                    const size_t target =
                        size_t(layer) * width * width + size_t(col) * width + common;
                    transposed_weights[target] =
                        static_cast<int8_t>(int32_t(weights[source]) - 125);
                }
            }
        }

        context->device_base = create_buffer(context->context, CL_MEM_READ_ONLY_FLAG,
                                             activation_len, "allocate base input");
        context->device_weights = create_buffer(context->context, CL_MEM_READ_ONLY_FLAG,
                                                expected_weights, "allocate weights");
        cl_check(api.EnqueueWriteBuffer(context->queue, context->device_base, CL_TRUE_VALUE, 0,
                                        activation_len, base_input, 0, nullptr, nullptr),
                 "copy base input");
        cl_check(api.EnqueueWriteBuffer(context->queue, context->device_weights, CL_TRUE_VALUE, 0,
                                        expected_weights, transposed_weights.data(), 0, nullptr,
                                        nullptr),
                 "copy weights");
        *output_context = context.release();
        return 0;
    } catch (const std::exception& exception) {
        write_error(error, error_len, exception.what());
        return 1;
    }
}

CMFD_CUDA_EXPORT int32_t cmfd_cuda_evaluate(void* opaque_context, const uint8_t* coefficients,
                                            size_t coefficients_len, uint32_t count,
                                            uint8_t* outputs, size_t outputs_len, char* error,
                                            size_t error_len) {
    try {
        if (opaque_context == nullptr) throw std::runtime_error("OpenCL context is null");
        if (count == 0 || count > MAX_BATCH) throw std::runtime_error("batch size is out of range");
        auto& context = *static_cast<Context*>(opaque_context);
        const size_t expected_coefficients =
            size_t(count) * (context.layers + 1) * context.coefficient_count;
        const size_t expected_outputs = size_t(count) * context.activation_len;
        if (coefficients == nullptr || coefficients_len != expected_coefficients ||
            outputs == nullptr || outputs_len != expected_outputs) {
            throw std::runtime_error("batch buffer length mismatch");
        }
        validate_canonical(coefficients, coefficients_len, "mask coefficients");

        const OpenClApi& api = opencl();
        ensure_capacity(context, count);
        cl_check(api.EnqueueWriteBuffer(context.queue, context.device_coefficients, CL_TRUE_VALUE,
                                        0, coefficients_len, coefficients, 0, nullptr, nullptr),
                 "copy mask coefficients");

        cl_check(api.SetKernelArg(context.kernel, 0, sizeof(cl_mem), &context.device_base),
                 "bind base input");
        cl_check(api.SetKernelArg(context.kernel, 1, sizeof(cl_mem), &context.device_weights),
                 "bind weights");
        cl_check(api.SetKernelArg(context.kernel, 2, sizeof(cl_mem), &context.device_coefficients),
                 "bind mask coefficients");
        cl_check(api.SetKernelArg(context.kernel, 3, sizeof(cl_mem), &context.device_outputs),
                 "bind outputs");
        cl_check(api.SetKernelArg(context.kernel, 4, sizeof(uint32_t), &context.rows), "bind rows");
        cl_check(api.SetKernelArg(context.kernel, 5, sizeof(uint32_t), &context.width),
                 "bind width");
        cl_check(api.SetKernelArg(context.kernel, 6, sizeof(uint32_t), &context.layers),
                 "bind layers");
        cl_check(api.SetKernelArg(context.kernel, 7, sizeof(uint32_t), &context.coefficient_count),
                 "bind coefficient count");
        cl_check(api.SetKernelArg(context.kernel, 8, sizeof(uint32_t), &count), "bind batch count");

        const size_t local_size = THREADS;
        const size_t global_size = size_t(count) * THREADS;
        cl_check(api.EnqueueNDRangeKernel(context.queue, context.kernel, 1, nullptr, &global_size,
                                          &local_size, 0, nullptr, nullptr),
                 "launch ForgeMatrix v2 batch");
        cl_check(api.EnqueueReadBuffer(context.queue, context.device_outputs, CL_TRUE_VALUE, 0,
                                       outputs_len, outputs, 0, nullptr, nullptr),
                 "copy ForgeMatrix v2 outputs");
        cl_check(api.Finish(context.queue), "finish ForgeMatrix v2 batch");
        return 0;
    } catch (const std::exception& exception) {
        write_error(error, error_len, exception.what());
        return 1;
    }
}

CMFD_CUDA_EXPORT void cmfd_cuda_destroy(void* opaque_context) {
    delete static_cast<Context*>(opaque_context);
}
