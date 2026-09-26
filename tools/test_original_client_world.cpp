#include "original_client_world.h"

#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

void writeRaw(const std::filesystem::path& path, std::uint8_t type,
              std::uint8_t field13, std::uint32_t field24) {
    std::vector<std::uint8_t> bytes(bh176::kPhysicalBlockPayloadSize, 0);
    bytes[0] = type;
    bytes[bh176::kTileBytesPerPhysicalBlock] = field13;
    bytes[bh176::kTileBytesPerPhysicalBlock + 1] = static_cast<std::uint8_t>(field24);
    bytes[bh176::kTileBytesPerPhysicalBlock + 2] = static_cast<std::uint8_t>(field24 >> 8);
    bytes[bh176::kTileBytesPerPhysicalBlock + 3] = static_cast<std::uint8_t>(field24 >> 16);
    bytes[bh176::kTileBytesPerPhysicalBlock + 4] = static_cast<std::uint8_t>(field24 >> 24);
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    assert(out.good());
}

void writeIndex(const std::filesystem::path& root, const std::string& rows) {
    std::ofstream out(root / "blocks/index.tsv");
    out << "key_hex\tx\ty\tfile\traw_sha256\tbytes\n" << rows;
    assert(out.good());
}

}  // namespace

int main() {
    const auto root = std::filesystem::temp_directory_path() / "bh-original-client-world-test";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root / "blocks");
    writeRaw(root / "blocks/-2_3.raw", 17, 0xa5, 0x12345678);
    writeRaw(root / "blocks/0_0.raw", 29, 0x5a, 0x01020304);
    writeIndex(root,
        "2d325f33\t-2\t3\tblocks/-2_3.raw\t954394e953de740bdcad4ea4248552cd5a44bd89ddb4c74ea6f0f55ebcc414ac\t65541\n"
        "305f30\t0\t0\tblocks/0_0.raw\t07913b029ea32a2eb16000705916f84ef28c43610212f9a3cf2a1a5fe0aded84\t65541\n");

    bh176::OriginalClientWorld world;
    std::string error;
    assert(world.load(root, &error));
    assert(error.empty());
    assert(world.blockCount() == 2);
    const auto* block = world.blockAt(-2, 3);
    assert(block != nullptr && block->tiles[0].type() == 17);
    assert(block->physicalBlockField13 == 0xa5);
    assert(block->physicalBlockField24 == 0x12345678U);
    assert(world.blockAt(1, 3) == nullptr && "missing blocks are explicit cache misses");

    // Check that checksum mismatch is rejected and preserves previous state
    writeIndex(root,
        "2d325f33\t-2\t3\tblocks/-2_3.raw\tdeadbeef00000000000000000000000000000000000000000000000000000000\t65541\n");
    assert(!world.load(root, &error) && error.find("checksum") != std::string::npos);
    assert(world.blockCount() == 2 && "failed load must not destroy previous state");

    // Check that key_hex / coordinate mismatch is rejected
    writeIndex(root,
        "305f30\t-2\t3\tblocks/-2_3.raw\t954394e953de740bdcad4ea4248552cd5a44bd89ddb4c74ea6f0f55ebcc414ac\t65541\n");
    assert(!world.load(root, &error) && error.find("coordinate") != std::string::npos);
    assert(world.blockCount() == 2 && "failed load must not destroy previous state");

    writeIndex(root,
        "2d325f33\t-2\t3\tblocks/-2_3.raw\t954394e953de740bdcad4ea4248552cd5a44bd89ddb4c74ea6f0f55ebcc414ac\t65541\n"
        "2d325f33\t-2\t3\tblocks/-2_3.raw\t954394e953de740bdcad4ea4248552cd5a44bd89ddb4c74ea6f0f55ebcc414ac\t65541\n");
    assert(!world.load(root, &error) && error.find("duplicate") != std::string::npos);
    assert(world.blockCount() == 2 && "failed load must not destroy previous state");

    writeIndex(root, "2d325f33\t-2\t3\tblocks/-2_3.raw\t954394e953de740bdcad4ea4248552cd5a44bd89ddb4c74ea6f0f55ebcc414ac\t1\n");
    assert(!world.load(root, &error) && error.find("size") != std::string::npos);
    assert(world.blockCount() == 2);

    std::filesystem::remove_all(root);
}
