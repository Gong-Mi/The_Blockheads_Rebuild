#include "craftable_item_record.h"

namespace blockheads::recovered {
// header-only by design; this unit exists so the record is part of the recovered view library.
namespace {
static_assert(sizeof(CraftableItemRecord) == 124);
static_assert(alignof(CraftableItemRecord) == alignof(std::int32_t));
}  // namespace
}  // namespace blockheads::recovered
