#include "original_client_world.h"

#include <iostream>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: load_client_world <snapshot_root> [x y]" << std::endl;
        return 1;
    }

    bh176::OriginalClientWorld world;
    std::string error;
    if (!world.load(argv[1], &error)) {
        std::cerr << "LOAD_FAILED: " << error << std::endl;
        return 2;
    }

    std::cout << "OK blockCount=" << world.blockCount();
    if (argc >= 4) {
        int x = std::stoi(argv[2]);
        int y = std::stoi(argv[3]);
        const auto* block = world.blockAt(x, y);
        if (block) {
            std::cout << " tile0_type=" << static_cast<int>(block->tiles[0].type())
                      << " field13=" << static_cast<int>(block->physicalBlockField13)
                      << " field24=" << block->physicalBlockField24;
        } else {
            std::cout << " block_miss=1";
        }
    }
    std::cout << std::endl;
    return 0;
}
