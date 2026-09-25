#include "dynamic_object_registry.h"

#include <array>
#include <cassert>

namespace bh176 {
namespace {

const DynamicObjectTypeEntry kTypes[] = {
#include "dynamic_object_type_table.inc"
};

constexpr std::size_t kTypeCount = sizeof(kTypes) / sizeof(kTypes[0]);
static_assert(kTypeCount == 64, "the decoded classForDynamicObjectType matrix has 64 rows");

// Batches DYNAMIC_OBJECT_TYPE_OBJECTTYPE_MATRIX + DYNAMIC_OBJECT_NPCTYPE_MATRIX:
// these classes have no direct class-level `objectType` override, so their
// objectType value comes from the shared/inherited path and does not by itself
// identify the class.
constexpr int kSharedObjectTypeIds[] = {13, 25, 28, 35, 36, 39, 51, 63};

constexpr const char* kBaseStubReason =
    "stub: per-type loader not recovered; base fields only "
    "(uniqueID/pos_x/pos_y/floatPos from the decoded DynamicObject base loader)";

}  // namespace

const char* objectLoadStatusName(ObjectLoadStatus status) {
    switch (status) {
        case ObjectLoadStatus::Stub: return "stub";
        case ObjectLoadStatus::Recovered: return "recovered";
        case ObjectLoadStatus::Verified: return "verified";
    }
    return "unknown";
}

const DynamicObjectTypeEntry* dynamicObjectTypeTable(std::size_t& count) {
    count = kTypeCount;
    return kTypes;
}

bool dynamicObjectTypeHasSharedObjectType(int type_id) {
    for (const int id : kSharedObjectTypeIds) {
        if (id == type_id) return true;
    }
    return false;
}

ClientDynamicObject DynamicObjectRegistry::baseStub(int type_id,
                                                    const SaveDict& entry) {
    ClientDynamicObject object;
    object.type_id = type_id;
    std::size_t table_size = 0;
    const auto* table = dynamicObjectTypeTable(table_size);
    for (std::size_t i = 0; i < table_size; ++i) {
        if (table[i].type_id == type_id) {
            object.class_name = table[i].class_name;
            break;
        }
    }
    object.unique_id = SaveDict::unsignedLongValue(entry.objectForKey("uniqueID"));
    object.pos_x = static_cast<std::int32_t>(SaveDict::intValue(entry.objectForKey("pos_x")));
    object.pos_y = static_cast<std::int32_t>(SaveDict::intValue(entry.objectForKey("pos_y")));
    const SaveValue* float_pos = entry.objectForKey("floatPos");
    if (SaveDict::count(float_pos) >= 2) {
        object.float_pos_x = SaveDict::floatValue(entry.objectAtIndex(float_pos, 0));
        object.float_pos_y = SaveDict::floatValue(entry.objectAtIndex(float_pos, 1));
        object.has_float_pos = true;
    }
    object.status = ObjectLoadStatus::Stub;
    object.status_reason = kBaseStubReason;
    return object;
}

DynamicObjectRegistry::DynamicObjectRegistry() : slots_(kTypeCount) {
    for (std::size_t i = 0; i < kTypeCount; ++i) {
        const int type_id = kTypes[i].type_id;
        slots_[i].label = "base stub (type " + std::to_string(type_id) + ")";
        slots_[i].status = ObjectLoadStatus::Stub;
        slots_[i].factory = [type_id](const SaveDict& entry, std::string* error) {
            if (error) error->clear();
            return baseStub(type_id, entry);
        };
    }
}

void DynamicObjectRegistry::registerFactory(int type_id, Factory factory,
                                            const std::string& label,
                                            ObjectLoadStatus status) {
    assert(type_id >= 1 && type_id <= static_cast<int>(kTypeCount));
    assert(factory);
    Slot& slot = slots_[static_cast<std::size_t>(type_id - 1)];
    slot.factory = std::move(factory);
    slot.label = label;
    slot.status = status;
}

bool DynamicObjectRegistry::hasConcreteFactory(int type_id) const {
    if (type_id < 1 || type_id > static_cast<int>(kTypeCount)) return false;
    return slots_[static_cast<std::size_t>(type_id - 1)].status != ObjectLoadStatus::Stub;
}

ObjectLoadStatus DynamicObjectRegistry::statusOf(int type_id) const {
    if (type_id < 1 || type_id > static_cast<int>(kTypeCount)) {
        return ObjectLoadStatus::Stub;
    }
    return slots_[static_cast<std::size_t>(type_id - 1)].status;
}

const std::string& DynamicObjectRegistry::factoryLabel(int type_id) const {
    static const std::string unknown = "unregistered type";
    if (type_id < 1 || type_id > static_cast<int>(kTypeCount)) return unknown;
    return slots_[static_cast<std::size_t>(type_id - 1)].label;
}

bool DynamicObjectRegistry::construct(int type_id, const SaveDict& entry,
                                      ClientDynamicObject* out,
                                      std::string* error) const {
    if (type_id < 1 || type_id > static_cast<int>(kTypeCount)) {
        if (error) {
            *error = "dynamic object type " + std::to_string(type_id) +
                     " is outside the decoded 1..64 matrix";
        }
        return false;
    }
    const Slot& slot = slots_[static_cast<std::size_t>(type_id - 1)];
    *out = slot.factory(entry, error);
    if (out->status_reason.empty()) {
        out->status_reason = slot.label;
    }
    return true;
}

}  // namespace bh176
