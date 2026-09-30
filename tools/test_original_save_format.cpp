#include "original_save_format.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
#include <zlib.h>

namespace {

std::vector<std::uint8_t> gzip(const std::vector<std::uint8_t>& input) {
    z_stream stream{};
    assert(deflateInit2(&stream,
                        Z_BEST_SPEED,
                        Z_DEFLATED,
                        MAX_WBITS + 16,
                        8,
                        Z_DEFAULT_STRATEGY) == Z_OK);
    std::vector<std::uint8_t> output(compressBound(input.size()) + 32);
    stream.next_in = const_cast<Bytef*>(
            reinterpret_cast<const Bytef*>(input.data()));
    stream.avail_in = static_cast<uInt>(input.size());
    stream.next_out = output.data();
    stream.avail_out = static_cast<uInt>(output.size());
    assert(deflate(&stream, Z_FINISH) == Z_STREAM_END);
    output.resize(stream.total_out);
    deflateEnd(&stream);
    return output;
}

}  // namespace

int main() {
    using namespace bh176;
    static_assert(kTilesPerPhysicalBlock == 1024);
    static_assert(kTileBytesPerPhysicalBlock == 65536);
    static_assert(kPhysicalBlockPayloadSize == 65541);

    std::vector<std::uint8_t> raw(kPhysicalBlockPayloadSize, 0);
    raw[0] = 3;   // water TileType, proven by tileIsWater(Tile*)
    raw[1] = 0x26;
    raw[3] = 0x4d;
    raw[7] = 0x80;
    raw[20] = 0x34;
    raw[21] = 0x12;
    raw[kTileBytesPerPhysicalBlock] = 0xa5;
    raw[kTileBytesPerPhysicalBlock + 1] = 0x78;
    raw[kTileBytesPerPhysicalBlock + 2] = 0x56;
    raw[kTileBytesPerPhysicalBlock + 3] = 0x34;
    raw[kTileBytesPerPhysicalBlock + 4] = 0x12;

    PhysicalBlockPayload decoded;
    std::string error;
    assert(decodePhysicalBlockPayload(raw.data(), raw.size(), decoded, &error));
    assert(decoded.tiles[0].type() == 3);
    assert(decoded.tiles[0].backWallType() == 0x26);
    assert(decoded.tiles[0].contentsType() == 0x4d);
    assert(decoded.tiles[0].temperatureScaleByte() == 0x80);
    assert(decoded.tiles[0].temperatureOffset() == 0x1234);
    assert(decoded.physicalBlockField13 == 0xa5);
    assert(decoded.physicalBlockField24 == 0x12345678U);

    const std::vector<std::uint8_t> compressed = gzip(raw);
    PhysicalBlockPayload inflated;
    error.clear();
    assert(decodeGzipPhysicalBlock(compressed, inflated, &error));
    assert(inflated.tiles[0].raw == decoded.tiles[0].raw);
    assert(inflated.physicalBlockField13 == decoded.physicalBlockField13);
    assert(inflated.physicalBlockField24 == decoded.physicalBlockField24);

    raw.pop_back();
    error.clear();
    assert(!decodePhysicalBlockPayload(raw.data(), raw.size(), decoded, &error));
    assert(!error.empty());

    std::cout << "original-save-format: PASS\n";
    return 0;
}
