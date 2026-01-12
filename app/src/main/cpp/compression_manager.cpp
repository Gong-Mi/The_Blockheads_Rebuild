#include <string>
#include <vector>
#include <fstream>
#include <zstd.h>
#include <lz4.h>
#include <android/log.h>

#define LOG_TAG "CompressionManager"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

class CompressionManager {
public:
    enum Engine { ZSTD, LZ4 };
    static Engine selectedEngine;

    // --- CPU 探测：判断是否为 A76 以下架构 ---
    static void init() {
        std::ifstream cpuinfo("/proc/cpuinfo");
        std::string line;
        bool isHighEnd = false;
        
        while (std::getline(cpuinfo, line)) {
            // A76 的 CPU implementer 通常是 0x41, variant 是核心代号
            // 这里我们简化处理：通过判断是否有 L3 缓存特征或是核心标识
            // 真实生产环境会解析 /sys/devices/system/cpu/cpu0/regs/identification/midr_el1
            if (line.find("part") != std::string::npos) {
                // 示例：0xd0b (A76), 0xd0d (A77), 0xd41 (A78)
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

    static std::vector<uint8_t> compress(const void* src, size_t srcSize) {
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
};

CompressionManager::Engine CompressionManager::selectedEngine = CompressionManager::LZ4;
