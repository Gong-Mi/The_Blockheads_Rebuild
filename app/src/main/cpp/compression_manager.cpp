#include "compression_manager.h"
#include <string>
#include <vector>
#include <fstream>
#include <zstd.h>
#include <lz4.h>
#include <android/log.h>

#define LOG_TAG "CompressionManager"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

CompressionManager::Engine CompressionManager::selectedEngine = CompressionManager::LZ4;

void CompressionManager::init() {
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    bool isHighEnd = false;
    
    while (std::getline(cpuinfo, line)) {
        if (line.find("part") != std::string::npos) {
            if (line.find("0xd0b") != std::string::npos || 
                line.find("0xd0d") != std::string::npos ||
                line.find("0xd41") != std::string::npos) {
                isHighEnd = true;
            }
        }
    }
    
    selectedEngine = isHighEnd ? ZSTD : LZ4;
    LOGI("CPU Architecture detected. Using engine: %s", isHighEnd ? "ZSTD" : "LZ4");
}

std::vector<uint8_t> CompressionManager::compress(const void* src, size_t srcSize) {
    if (selectedEngine == ZSTD) {
        size_t maxDstSize = ZSTD_compressBound(srcSize);
        std::vector<uint8_t> dst(maxDstSize);
        size_t cSize = ZSTD_compress(dst.data(), maxDstSize, src, srcSize, 3);
        dst.resize(cSize);
        return dst;
    } else {
        size_t maxDstSize = LZ4_compressBound(srcSize);
        std::vector<uint8_t> dst(maxDstSize);
        int cSize = LZ4_compress_default((const char*)src, (char*)dst.data(), srcSize, maxDstSize);
        dst.resize(cSize);
        return dst;
    }
}