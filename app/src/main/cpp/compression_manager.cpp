#include <string>
#include <vector>
#include <zstd.h> // 需要在后续编译流中加入 zstd 源码

class CompressionManager {
public:
    // 压缩物理块
    static std::vector<uint8_t> compressChunk(const void* src, size_t srcSize) {
        size_t const maxDstSize = ZSTD_compressBound(srcSize);
        std::vector<uint8_t> dst(maxDstSize);
        
        // 使用等级 3 (平衡速度与压缩率)
        size_t const cSize = ZSTD_compress(dst.data(), maxDstSize, src, srcSize, 3);
        dst.resize(cSize);
        return dst;
    }

    // 解压物理块
    static void decompressChunk(const void* src, size_t cSize, void* dst, size_t dstSize) {
        ZSTD_decompress(dst, dstSize, src, cSize);
    }
};
