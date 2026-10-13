#ifndef DYNAMIC_OBJECT_REGISTRY_H
#define DYNAMIC_OBJECT_REGISTRY_H

// Client-app entity registry (skeleton).
//
// type_id 1..64 comes from the decoded `_Z25classForDynamicObjectTypei` jump
// table: app/src/main/cpp/generated/dynamic_object_type_table.inc is generated
// by tools/gen_dynamic_object_type_table.py from
// reconstruction/reverse-v3/native/dynamicobject_type_matrix.json and gated by
// `--check`, so no class name here is invented or transcribed by hand.
//
// Every type starts as a STUB: only the already-decoded base loader fields are
// read (uniqueID -> unsignedLongValue, pos_x/pos_y -> intValue,
// floatPos -> objectAtIndex:0/1 -> floatValue). Nothing else is inferred from
// the key shape, and there is no placeholder that silently succeeds.
//
// Recovery batches plug in concrete loaders with registerFactory(); the status
// only becomes Recovered (toolchain-verified decode) or Verified (executed
// differential) when the caller registers it as such.
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "original_save_dict.h"

namespace bh176 {

enum class ObjectLoadStatus { Stub, Recovered, Verified };
const char* objectLoadStatusName(ObjectLoadStatus status);

// A recovered state is OWNED by the object that ran the recovered chain.
// The family name is the module struct that decoded it (e.g. "PlantFullState"):
// a Recovered/Verified status without a state is refused by construct() —
// that is the structural end of the "factory ran, state dropped" discard bug.
struct RecoveredState {
    virtual ~RecoveredState() = default;
    virtual const char* familyName() const = 0;
};

template <typename State>
class ModuleState final : public RecoveredState {
public:
    ModuleState(State value, const char* family)
        : value_(std::move(value)), family_(family) {}
    const State& value() const { return value_; }
    const char* familyName() const override { return family_; }

private:
    State value_;
    const char* family_;
};

struct DynamicObjectTypeEntry {
    int type_id;
    const char* class_name;
    const char* jump_target;
};

// The decoded 1..64 table (64 rows, compile-time asserted).
const DynamicObjectTypeEntry* dynamicObjectTypeTable(std::size_t& count);

// The 8 type ids whose classes have no direct `objectType` override (shared /
// inherited path, batch DYNAMIC_OBJECT_TYPE_OBJECTTYPE_MATRIX): a raw type id
// alone does not identify the class for them.
bool dynamicObjectTypeHasSharedObjectType(int type_id);

struct ClientDynamicObject {
    int type_id = 0;
    std::string class_name;
    // Base-loader fields only, each from its decoded key.
    std::uint64_t unique_id = 0;
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    float float_pos_x = 0.0f;
    float float_pos_y = 0.0f;
    bool has_float_pos = false;
    ObjectLoadStatus status = ObjectLoadStatus::Stub;
    std::string status_reason;
    // the decoded per-module state this object ran to produce; present exactly
    // when status is Recovered/Verified (construct() enforces the pairing)
    std::shared_ptr<const RecoveredState> state;

    // Typed read-back: exact family match, nullptr otherwise (no reinterpret).
    template <typename State>
    const State* stateAs(const char* family) const {
        if (state == nullptr || std::string_view(state->familyName()) != family) {
            return nullptr;
        }
        return &static_cast<const ModuleState<State>*>(state.get())->value();
    }
};

// The recovered chain ran for real; the object now owns its decoded state.
// `family` must be the module struct name the state came from.
template <typename State>
void attachRecoveredState(ClientDynamicObject& object, State value,
                          ObjectLoadStatus status, std::string reason,
                          const char* family) {
    object.state = std::make_shared<const ModuleState<State>>(
        std::move(value), family);
    object.status = status;
    object.status_reason = std::move(reason);
}

class DynamicObjectRegistry {
public:
    using Factory = std::function<ClientDynamicObject(const SaveDict& entry, std::string* error)>;

    DynamicObjectRegistry();

    // Registers (or replaces) the loader for one type id. `status` must be
    // Recovered/Verified only when the caller really has that evidence.
    void registerFactory(int type_id, Factory factory, const std::string& label,
                         ObjectLoadStatus status);
    bool hasConcreteFactory(int type_id) const;
    ObjectLoadStatus statusOf(int type_id) const;
    const std::string& factoryLabel(int type_id) const;

    // Unknown type ids (outside 1..64) are refused, never guessed.
    bool construct(int type_id, const SaveDict& entry, ClientDynamicObject* out,
                   std::string* error) const;

    // The default per-type stub body (public so tests and later batches reuse
    // exactly the same base-field reading).
    static ClientDynamicObject baseStub(int type_id, const SaveDict& entry);

private:
    struct Slot {
        Factory factory;
        std::string label;
        ObjectLoadStatus status = ObjectLoadStatus::Stub;
    };
    std::vector<Slot> slots_;  // index == type_id - 1
};

}  // namespace bh176

#endif  // DYNAMIC_OBJECT_REGISTRY_H
