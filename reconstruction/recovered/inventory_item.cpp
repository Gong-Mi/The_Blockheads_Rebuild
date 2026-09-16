#include "inventory_item.h"

#include <algorithm>
#include <atomic>
#include <stdexcept>
#include <utility>

namespace blockheads::recovered {
namespace {
std::uint16_t read16(const std::array<std::uint8_t, 8>& b, std::size_t at) {
    return static_cast<std::uint16_t>(b[at] | (static_cast<std::uint16_t>(b[at + 1]) << 8));
}
void write16(std::array<std::uint8_t, 8>& b, std::size_t at, std::uint16_t v) {
    b[at] = static_cast<std::uint8_t>(v);
    b[at + 1] = static_cast<std::uint8_t>(v >> 8);
}
// Mirrors observed dmb instructions, NOT a claim of thread-safe vector mutation.
void barrier() { std::atomic_thread_fence(std::memory_order_seq_cst); }
InventoryBytes saveChild(InventoryRuntime& r, const InventoryItem::Ptr& child) {
    // nil saveData followed by NSMutableArray addObject:nil is invalid.
    if (!child) throw std::invalid_argument("InventoryItem: nil child data cannot be added to array");
    return child->saveData(r);
}
InventoryItem::Ptr loadChild(InventoryRuntime& r, const InventoryBytes& data) {
    auto child = InventoryItem::initWithSaveData(r, data);
    if (!child) throw std::invalid_argument("InventoryItem: nil initialized child cannot be added to array");
    return child;
}
}

std::int32_t InventoryItem::subItemSlotCount(std::int32_t type) {
    // Entire numeric helper @0xac5b4c..0xac5cd8. No inferred enum labels.
    switch (type) {
    case 1: case 12: case 161: case 207: return 4;
    case 45: return 2;
    case 0x413: case 0x429: case 0x430: case 0x432: case 0x450: return 16;
    default: return 0;
    }
}

InventoryItem::Ptr InventoryItem::initWithType(InventoryRuntime& runtime,
        std::int32_t type, std::uint16_t a, std::uint16_t b,
        SlotsPtr input, InventoryObject dynamic) {
    if (!runtime.initializeItem()) return nullptr; // @ac56d4
    auto self = std::make_shared<InventoryItem>();
    self->type_ = type;
    self->a_ = a;
    self->b_ = b;
    self->dynamic_ = std::move(dynamic); // retain identity, @ac5768/ac577c
    const auto count = subItemSlotCount(type);
    if (count > 0) { // @ac57a4
        auto slots = std::make_shared<Slots>();
        slots->reserve(static_cast<std::size_t>(count));
        for (std::int32_t index = 0; index < count; ++index) {
            auto slot = std::make_shared<Slot>();
            if (input && input->size() > static_cast<std::uint32_t>(index)) { // @ac5870
                const auto& source = input->at(static_cast<std::size_t>(index));
                if (source) {
                    for (const auto& child : *source) {
                        if (!child) throw std::invalid_argument("InventoryItem: addObject:nil");
                        slot->push_back(child); // not copy/serialize child @ac59e0
                    }
                }
            }
            slots->push_back(std::move(slot));
        }
        self->slots_ = std::move(slots); // immutable outer copy @ac5ad4
    }
    return self;
}

InventoryItem::Ptr InventoryItem::initWithSaveData(InventoryRuntime& runtime, const InventoryBytes& data) {
    if (!runtime.initializeItem()) return nullptr; // @ac5e4c
    auto self = std::make_shared<InventoryItem>();
    // Original copies min(length,8) into an UNINITIALIZED stack struct.
    // Supply that indeterminate state explicitly: do not manufacture defaults.
    auto bytes = runtime.headerStackImage(InventoryHeaderUse::Load);
    std::copy_n(data.begin(), std::min<std::size_t>(data.size(), 8), bytes.begin());
    self->type_ = read16(bytes, 0); // unsigned halfword widened to ItemType int32
    self->a_ = read16(bytes, 2);
    self->b_ = read16(bytes, 4);
    self->selected_ = bytes[6];
    InventoryTail tail;
    if (data.size() > 8) { // @ac5fe8
        InventoryBytes compressed(data.begin() + 8, data.end());
        auto inflated = runtime.gzipInflate(compressed); // @ac6084
        tail = runtime.propertyListDecode(inflated, 0); // @ac6088 -> ac64b0 -> ac76a8
        self->dynamic_ = tail.dynamicObject; // "d", retain @ac6100/ac6114
    }
    const auto count = subItemSlotCount(self->type_);
    if (count > 0) {
        auto slots = std::make_shared<Slots>();
        slots->reserve(static_cast<std::size_t>(count));
        for (std::int32_t index = 0; index < count; ++index) {
            auto slot = std::make_shared<Slot>();
            // Original has NO count guard here. Missing key is nil (empty);
            // present but short NSArray throws at objectAtIndex: @ac6230.
            if (tail.subItems) {
                for (const auto& childData : tail.subItems->at(static_cast<std::size_t>(index)))
                    slot->push_back(loadChild(runtime, childData));
            }
            slots->push_back(std::move(slot));
        }
        self->slots_ = std::move(slots);
    }
    return self;
}

InventoryBytes InventoryItem::saveData(InventoryRuntime& runtime) const {
    auto header = runtime.headerStackImage(InventoryHeaderUse::Save);
    write16(header, 0, static_cast<std::uint16_t>(type_)); // @ac658c truncation
    write16(header, 2, a_);
    write16(header, 4, b_);
    header[6] = selected_; // byte 7 is never written by original @ac65d4..ac6624
    InventoryBytes data(header.begin(), header.end());
    InventoryTail tail;
    if (slots_ && !slots_->empty()) {
        bool hasAnyItem = false;
        InventorySavedSlots saved;
        saved.reserve(slots_->size());
        for (const auto& slot : *slots_) {
            InventorySavedSlot savedSlot;
            if (slot) {
                for (const auto& child : *slot) {
                    hasAnyItem = true; // @ac6924; NOT merely slots count > 0
                    savedSlot.push_back(saveChild(runtime, child));
                }
            }
            saved.push_back(std::move(savedSlot));
        }
        if (hasAnyItem) tail.subItems = std::move(saved); // @ac6aa8
    }
    if (dynamic_) tail.dynamicObject = dynamic_; // pointer nonnil, not dictionary count
    if (tail.subItems || tail.dynamicObject) { // dictionary count @ac6ba4
        auto plist = runtime.propertyListEncode(tail, 100, 0); // @ac6cd4 XML, not binary 200
        auto compressed = runtime.gzipDeflate(plist);
        runtime.appendData(data, compressed);
    }
    return data;
}

void InventoryItem::updateSubItemSlot(InventoryRuntime& runtime,
                                     const InventorySavedSlot& data, std::int32_t index) {
    const auto count = slots_ ? slots_->size() : 0;
    // Deliberately strict '<', not '<=': equality reaches original NSArray exception.
    if (count < static_cast<std::uint32_t>(index)) return; // @ac6e3c unsigned
    auto slot = slots_ ? slots_->at(static_cast<std::uint32_t>(index)) : nullptr;
    if (slot) slot->clear(); // @ac6ef0 before any recursive allocation
    for (const auto& childData : data) {
        auto child = initWithSaveData(runtime, childData);
        if (slot) {
            if (!child) throw std::invalid_argument("InventoryItem: addObject:nil");
            slot->push_back(std::move(child));
        } // nil target still allocates/initializes/autoreleases each child
    }
}

std::optional<InventorySavedSlot> InventoryItem::subItemSlotDataAtIndex(
        InventoryRuntime& runtime, std::int32_t index) const {
    const auto count = slots_ ? slots_->size() : 0;
    if (count < static_cast<std::uint32_t>(index)) return std::nullopt; // @ac718c
    auto slot = slots_ ? slots_->at(static_cast<std::uint32_t>(index)) : nullptr;
    InventorySavedSlot result;
    if (slot) for (const auto& child : *slot) result.push_back(saveChild(runtime, child));
    return result;
}

std::int32_t InventoryItem::itemType() const { auto v = type_; barrier(); return v; }
InventoryItem::SlotsPtr InventoryItem::subItems() const { auto v = slots_; barrier(); return v; }
std::uint8_t InventoryItem::selectedSubItemIndex() const { return selected_; }
void InventoryItem::setSelectedSubItemIndex(std::uint8_t v) { barrier(); selected_ = v; barrier(); }
std::uint16_t InventoryItem::dataA() const { return a_; }
void InventoryItem::setDataA(std::uint16_t v) { barrier(); a_ = v; barrier(); }
std::uint16_t InventoryItem::dataB() const { return b_; }
void InventoryItem::setDataB(std::uint16_t v) { barrier(); b_ = v; barrier(); }
InventoryObject InventoryItem::dynamicObjectSaveDict() const { auto v = dynamic_; barrier(); return v; }
} // namespace blockheads::recovered
