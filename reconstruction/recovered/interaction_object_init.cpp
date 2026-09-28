// InteractionObject loader contract implementation. See the header for the
// decoded shape (all statements pinned by the annotated listing).
#include "interaction_object_init.h"

#include <cstring>

namespace blockheads::recovered {

namespace {

using Call = InteractionInitCall;

void storeWord(std::uint8_t* image, std::size_t offset, std::uint32_t value) {
    std::memcpy(image + offset, &value, sizeof(value));
}

void storeHalf(std::uint8_t* image, std::size_t offset, std::uint32_t value) {
    const std::uint16_t truncated = static_cast<std::uint16_t>(value & 0xffffu);
    std::memcpy(image + offset, &truncated, sizeof(truncated));
}

void storeByte(std::uint8_t* image, std::size_t offset, std::uint32_t value) {
    image[offset] = static_cast<std::uint8_t>(value & 0xffu);
}

}  // namespace

InteractionInitResult interaction_init_run(const InteractionInitInputs& in) {
    InteractionInitResult result;
    result.image.assign(kInteractionImageSize, 0);
    auto& calls = result.calls;
    std::uint8_t* image = result.image.data();

    // super forward (objc_msgSendSuper2 with the own-class superref); a nil
    // super result returns nil before any key read.
    calls.push_back(Call::SuperInit);
    if (in.super_returns_nil) {
        result.return_value = 0;
        return result;
    }
    result.return_value = in.self_ptr;

    // isInUse -> boolValue -> strb @68 (nil decodes as 0, like the original)
    calls.push_back(Call::ObjectForKeyIsInUse);
    calls.push_back(Call::BoolValueIsInUse);
    storeByte(image, 68, (in.in_use_present && in.in_use_value) ? 1u : 0u);

    // flipped -> boolValue -> strb @69
    calls.push_back(Call::ObjectForKeyFlipped);
    calls.push_back(Call::BoolValueFlipped);
    storeByte(image, 69, (in.flipped_present && in.flipped_value) ? 1u : 0u);

    // ownerID -> retain -> str @36
    calls.push_back(Call::ObjectForKeyOwnerID);
    calls.push_back(Call::RetainOwnerID);
    storeWord(image, 36, in.owner_id_present ? in.owner_id_token : 0u);

    // ownerName -> retain -> str @84
    calls.push_back(Call::ObjectForKeyOwnerName);
    calls.push_back(Call::RetainOwnerName);
    storeWord(image, 84, in.owner_name_present ? in.owner_name_token : 0u);

    // paintColor -> unsignedIntValue -> STRH @88 (halfword store; nil -> 0)
    calls.push_back(Call::ObjectForKeyPaintColor);
    calls.push_back(Call::UnsignedIntValuePaintColor);
    storeHalf(image, 88, in.paint_color_present ? in.paint_color_value : 0u);

    // currentBlockheadIndex: probe; the second read + intValue + store only
    // run when the probe is non-nil (the beq skip at 0x5f4980).
    calls.push_back(Call::ObjectForKeyCurrentBlockheadIndexProbe);
    if (in.blockhead_index_present) {
        calls.push_back(Call::ObjectForKeyCurrentBlockheadIndex);
        calls.push_back(Call::IntValueCurrentBlockheadIndex);
        storeWord(image, 80, static_cast<std::uint32_t>(in.blockhead_index_value));
    }

    // tail: [dynamicWorld isServer] gate, then the ownerID non-nil gate;
    // only then the world-side name resolution is retained into ownerName@84.
    calls.push_back(Call::IsServer);
    if (in.is_server) {
        std::uint32_t current_owner_id = 0;
        std::memcpy(&current_owner_id, image + 36, sizeof(current_owner_id));
        if (current_owner_id != 0) {  // ownerID@36 non-nil gate
            calls.push_back(Call::GetOwnerNameForObjectOwnerID);
            calls.push_back(Call::RetainResolvedOwnerName);
            storeWord(image, 84, in.resolved_owner_name_token);
        }
    }
    return result;
}

}  // namespace blockheads::recovered
