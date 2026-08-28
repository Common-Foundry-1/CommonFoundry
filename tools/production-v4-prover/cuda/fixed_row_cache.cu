#include <cuda_runtime.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>

namespace {

constexpr size_t ROWS = size_t{1} << 24;
constexpr size_t COLUMNS = 256;
constexpr size_t BLOCK_ROWS = size_t{1} << 20;
constexpr size_t VALUES = ROWS * COLUMNS;
constexpr size_t BYTES = VALUES * sizeof(uint32_t);
constexpr unsigned THREADS = 256;

void cuda_check(cudaError_t result, const char* operation) {
    if (result != cudaSuccess) {
        throw std::runtime_error(std::string(operation) + ": " + cudaGetErrorString(result));
    }
}

void write_all(int descriptor, const void* bytes, size_t count) {
    const auto* cursor = static_cast<const uint8_t*>(bytes);
    while (count != 0) {
        const ssize_t written = write(descriptor, cursor, count);
        if (written <= 0) throw std::runtime_error("write row-major cache");
        cursor += written;
        count -= static_cast<size_t>(written);
    }
}

__global__ void transpose_block(const uint32_t* column_major,
                                uint32_t* row_major,
                                size_t rows) {
    for (size_t index = size_t(blockIdx.x) * blockDim.x + threadIdx.x;
         index < rows * COLUMNS;
         index += size_t(gridDim.x) * blockDim.x) {
        const size_t row = index / COLUMNS;
        const size_t column = index % COLUMNS;
        row_major[index] = column_major[column * rows + row];
    }
}

void convert(const char* source_path, const char* destination_path) {
    const int source = open(source_path, O_RDONLY);
    if (source < 0) throw std::runtime_error("open column-major codeword");
    struct stat metadata {};
    if (fstat(source, &metadata) != 0 || static_cast<size_t>(metadata.st_size) != BYTES) {
        throw std::runtime_error("column-major codeword has the wrong byte length");
    }
    const auto* mapped = static_cast<const uint32_t*>(
        mmap(nullptr, BYTES, PROT_READ, MAP_SHARED, source, 0));
    if (mapped == MAP_FAILED) throw std::runtime_error("map column-major codeword");
    const int destination = open(destination_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (destination < 0) throw std::runtime_error("create row-major codeword");

    const size_t block_values = BLOCK_ROWS * COLUMNS;
    uint32_t* host_column = nullptr;
    uint32_t* host_row = nullptr;
    uint32_t* device_column = nullptr;
    uint32_t* device_row = nullptr;
    cuda_check(cudaMallocHost(&host_column, block_values * sizeof(uint32_t)),
               "allocate pinned column block");
    cuda_check(cudaMallocHost(&host_row, block_values * sizeof(uint32_t)),
               "allocate pinned row block");
    cuda_check(cudaMalloc(&device_column, block_values * sizeof(uint32_t)),
               "allocate device column block");
    cuda_check(cudaMalloc(&device_row, block_values * sizeof(uint32_t)),
               "allocate device row block");

    const auto started = std::chrono::steady_clock::now();
    for (size_t first_row = 0; first_row < ROWS; first_row += BLOCK_ROWS) {
        for (size_t column = 0; column < COLUMNS; ++column) {
            std::memcpy(host_column + column * BLOCK_ROWS,
                        mapped + column * ROWS + first_row,
                        BLOCK_ROWS * sizeof(uint32_t));
        }
        cuda_check(cudaMemcpy(device_column, host_column,
                              block_values * sizeof(uint32_t),
                              cudaMemcpyHostToDevice),
                   "upload column block");
        const unsigned blocks = static_cast<unsigned>(
            (block_values + THREADS - 1) / THREADS);
        transpose_block<<<blocks, THREADS>>>(device_column, device_row, BLOCK_ROWS);
        cuda_check(cudaGetLastError(), "transpose codeword block");
        cuda_check(cudaMemcpy(host_row, device_row,
                              block_values * sizeof(uint32_t),
                              cudaMemcpyDeviceToHost),
                   "download row block");
        write_all(destination, host_row, block_values * sizeof(uint32_t));
        if ((first_row / BLOCK_ROWS) % 32 == 31) {
            std::printf("progress_rows=%zu\n", first_row + BLOCK_ROWS);
            std::fflush(stdout);
        }
    }
    if (fsync(destination) != 0) throw std::runtime_error("flush row-major codeword");
    const double seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - started).count();
    std::printf("row_major_cache=COMPLETE bytes=%zu seconds=%.6f\n", BYTES, seconds);

    cudaFree(device_row);
    cudaFree(device_column);
    cudaFreeHost(host_row);
    cudaFreeHost(host_column);
    close(destination);
    munmap(const_cast<uint32_t*>(mapped), BYTES);
    close(source);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "usage: fixed_row_cache <column-major> <row-major>\n");
        return 2;
    }
    try {
        convert(argv[1], argv[2]);
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "error: %s\n", error.what());
        return 1;
    }
}
