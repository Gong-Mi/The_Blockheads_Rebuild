// Contract test for the recovered DynamicObjectNetData header and its family.
#include "dynamic_object_net_data.h"

#include <cassert>
#include <cstddef>
#include <cstdio>
#include <initializer_list>

using namespace blockheads::recovered;

int main() {
    assert(sizeof(DynamicObjectNetData) == 24);

    // the layout the encoding implies: Q, I, I, C, [7C]
    assert(offsetof(DynamicObjectNetData, f0) == 0);
    assert(offsetof(DynamicObjectNetData, f1) == 8);
    assert(offsetof(DynamicObjectNetData, f2) == 12);
    assert(offsetof(DynamicObjectNetData, f3) == 16);
    assert(offsetof(DynamicObjectNetData, f4) == 17);
    assert(sizeof(DynamicObjectNetData::f0) == 8);
    assert(sizeof(DynamicObjectNetData::f4) == 7);
    // the trailing byte array runs to the end of the record: no padding, which is why the size is exactly 24
    assert(offsetof(DynamicObjectNetData, f4) + sizeof(DynamicObjectNetData::f4) == sizeof(DynamicObjectNetData));

    // the family sizes, from the census
    assert(kNPCUpdateNetDataSize == 24);
    assert(kPlantCreationNetDataSize == 40);
    assert(kInteractionObjectCreationNetDataSize == 40);
    assert(kNPCCreationNetDataSize == 72);
    assert(kTrainCarCreationNetDataSize == 104);
    // every one of them is larger than or equal to the header they all start with
    for (std::size_t s : {kNPCUpdateNetDataSize, kPlantCreationNetDataSize,
                          kInteractionObjectCreationNetDataSize, kNPCCreationNetDataSize,
                          kTrainCarCreationNetDataSize}) {
        assert(s >= sizeof(DynamicObjectNetData));
    }

    std::puts("dynamic-object-net-data: PASS");
    return 0;
}
