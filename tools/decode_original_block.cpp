// Host adapter for the production client decoder; no replacement decoder.
#include "original_save_format.h"
#include <fstream>
#include <iterator>
#include <iostream>
int main(int argc,char**argv){
 if(argc!=3)return 2;
 std::ifstream in(argv[1],std::ios::binary);
 if(!in)return 3;
 std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(in)),{});
 bh176::PhysicalBlockPayload block;std::string error;
 if(!bh176::decodeGzipPhysicalBlock(data,block,&error)){std::cerr<<error<<'\n';return 4;}
 std::ofstream out(argv[2],std::ios::binary);if(!out)return 5;
 for(const auto&tile:block.tiles)out.write(reinterpret_cast<const char*>(tile.raw.data()),tile.raw.size());
 out.put(static_cast<char>(block.physicalBlockField13));
 for(unsigned i=0;i<4;++i)out.put(static_cast<char>((block.physicalBlockField24>>(8*i))&255));
 return out?0:6;
}
