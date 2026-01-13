#ifndef COMPRESSION_MANAGER_H
#define COMPRESSION_MANAGER_H

#include <vector>
#include <stdint.h>
#include <cstddef>

class CompressionManager {
public:
    enum Engine { ZSTD, LZ4 };
    static Engine selectedEngine;

    static void init();
    static std::vector<uint8_t> compress(const void* src, size_t srcSize);
};

#endif
