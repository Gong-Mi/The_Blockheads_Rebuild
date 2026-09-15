#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace blockheads::recovered {
using InventoryBytes = std::vector<std::uint8_t>;
// Deliberately opaque: no assumptions about a dynamic object's dictionary schema.
struct InventoryRuntimeObject { virtual ~InventoryRuntimeObject() = default; };
using InventoryObject = std::shared_ptr<InventoryRuntimeObject>;
using InventorySavedSlot = std::vector<InventoryBytes>;
using InventorySavedSlots = std::vector<InventorySavedSlot>;
struct InventoryTail {
    InventoryObject dynamicObject; // original dictionary key "d"
    std::optional<InventorySavedSlots> subItems; // original key "s"; missing != empty
};
enum class InventoryHeaderUse { Load, Save };

// Logical recovery domain: newly allocated ordinary items; stable ordinary arrays;
// no concurrent/reentrant structural mutation, subclass dispatch, or alloc/init/retain
// object substitution. The original IMPs re-read ivars/counts around ObjC calls;
// these typed vectors and direct child calls are NOT full ObjC dynamic equivalence.
// Mandatory external Foundation/NSData boundary. There is NO production codec stub.
// Implementations must preserve nil and the original helpers' exception handling.
// headerStackImage supplies otherwise indeterminate bytes without C++ undefined
// reads; it is an evidence-model input, NOT an original runtime callback.
// See reconstruction/reverse-v3/native/INVENTORY_ITEM.md for exact limits.
class InventoryRuntime {
public:
    virtual ~InventoryRuntime() = default;
    virtual bool initializeItem() = 0; // NSObject init nil/success gate; see evidence limits
    virtual std::array<std::uint8_t, 8> headerStackImage(InventoryHeaderUse) = 0;
    virtual std::optional<InventoryBytes> gzipInflate(const InventoryBytes&) = 0;
    virtual InventoryTail propertyListDecode(const std::optional<InventoryBytes>&,
                                             std::uint32_t options) = 0;
    virtual std::optional<InventoryBytes> propertyListEncode(const InventoryTail&,
                                  std::uint32_t format, std::uint32_t options) = 0;
    virtual std::optional<InventoryBytes> gzipDeflate(const std::optional<InventoryBytes>&) = 0;
    virtual void appendData(InventoryBytes&, const std::optional<InventoryBytes>&) = 0;
};

class InventoryItem {
public:
    using Ptr = std::shared_ptr<InventoryItem>;
    using Slot = std::vector<Ptr>;
    using SlotPtr = std::shared_ptr<Slot>;
    using Slots = std::vector<SlotPtr>;
    // Outer NSArray copy is immutable; inner NSMutableArrays remain mutable.
    using SlotsPtr = std::shared_ptr<const Slots>;

    static std::int32_t subItemSlotCount(std::int32_t type);
    static Ptr initWithType(InventoryRuntime&, std::int32_t type, std::uint16_t dataA,
                std::uint16_t dataB, SlotsPtr subItems, InventoryObject dynamicObjectSaveDict);
    static Ptr initWithSaveData(InventoryRuntime&, const InventoryBytes&);
    InventoryBytes saveData(InventoryRuntime&) const;
    void updateSubItemSlot(InventoryRuntime&, const InventorySavedSlot&, std::int32_t index);
    std::optional<InventorySavedSlot> subItemSlotDataAtIndex(InventoryRuntime&, std::int32_t index) const;

    std::int32_t itemType() const;
    SlotsPtr subItems() const;
    std::uint8_t selectedSubItemIndex() const;
    void setSelectedSubItemIndex(std::uint8_t);
    std::uint16_t dataA() const;
    void setDataA(std::uint16_t);
    std::uint16_t dataB() const;
    void setDataB(std::uint16_t);
    InventoryObject dynamicObjectSaveDict() const;
private:
    std::int32_t type_ = 0;
    std::uint16_t a_ = 0, b_ = 0;
    std::uint8_t selected_ = 0;
    SlotsPtr slots_;
    InventoryObject dynamic_;
};
} // namespace blockheads::recovered
