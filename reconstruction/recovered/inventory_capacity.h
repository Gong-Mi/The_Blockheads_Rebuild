#pragma once
#include <array>
#include <cstdint>
#include <cstddef>

namespace recovered::inventory_capacity {
using Object = std::uintptr_t; // opaque identity; zero is ObjC nil, never a C++ Item pointer
struct EnumerationState {
    std::uintptr_t state = 0;
    Object* items = nullptr;
    std::uint32_t* mutations = nullptr;
    std::array<std::uintptr_t, 5> extra{};
};
// Dynamic sends and ivar loads are explicit, including calls on nil. Implementors
// supply their real object runtime. No fixed-size primitive inventory is assumed.
struct Runtime {
    virtual ~Runtime() = default;
    virtual Object readWorld(Object receiver) = 0; // DynamicObject.world
    virtual Object readInventoryItems(Object receiver) = 0; // Blockhead.inventoryItems
    virtual std::int8_t worldUIDragging(Object world) = 0;
    virtual Object objectAtIndex(Object array, std::uint32_t index) = 0;
    virtual std::uint32_t count(Object array) = 0;
    virtual std::int32_t itemType(Object item) = 0;
    virtual std::uint16_t dataB(Object item) = 0;
    virtual Object subItems(Object item) = 0;
    virtual std::uint32_t enumerate(Object array, EnumerationState& state,
                                   Object* buffer, std::uint32_t capacity) = 0;
    virtual void enumerationMutation(Object array) = 0;
    // Wrapper is a dynamic send, not a static call to the recovered implementation.
    virtual std::int32_t sendCanPickUp(Object receiver, std::int32_t type,
                                     Object subItems, std::uint16_t a,
                                     std::uint16_t b) = 0;
};
std::int32_t subItemCapacityAtC5EAA8(std::int32_t type); // original symbol name not exported
// Exact integer classification: 0 invalid/dragging, 1 fit, -1 exhausted.
std::int32_t canPickUpItemOfType(Runtime&, Object receiver, std::int32_t type, Object subItems);
std::int32_t canPickUpItemOfType(Runtime&, Object receiver, std::int32_t type, Object subItems,
                               std::uint16_t dataA, std::uint16_t dataB);
}
