#include "chest_init_with_world.h"

#include <algorithm>

namespace blockheads::recovered {

namespace {

void store_word(std::vector<std::uint8_t>& image, std::size_t offset,
                std::uint32_t val) {
    if (offset + 4 <= image.size()) {
        image[offset + 0] = static_cast<std::uint8_t>(val & 0xff);
        image[offset + 1] = static_cast<std::uint8_t>((val >> 8) & 0xff);
        image[offset + 2] = static_cast<std::uint8_t>((val >> 16) & 0xff);
        image[offset + 3] = static_cast<std::uint8_t>((val >> 24) & 0xff);
    }
}

void store_half(std::vector<std::uint8_t>& image, std::size_t offset,
                std::uint16_t val) {
    if (offset + 2 <= image.size()) {
        image[offset + 0] = static_cast<std::uint8_t>(val & 0xff);
        image[offset + 1] = static_cast<std::uint8_t>((val >> 8) & 0xff);
    }
}

std::uint32_t load_word(const std::vector<std::uint8_t>& image,
                        std::size_t offset) {
    if (offset + 4 > image.size()) return 0;
    return static_cast<std::uint32_t>(image[offset + 0]) |
           (static_cast<std::uint32_t>(image[offset + 1]) << 8) |
           (static_cast<std::uint32_t>(image[offset + 2]) << 16) |
           (static_cast<std::uint32_t>(image[offset + 3]) << 24);
}

}  // namespace

int chest_slot_capacity(std::int32_t chest_type) {
    // 0x00CB623C: cmp #2 / cmp #5 -> movw #4, else movw #0x10.
    return (chest_type == 2 || chest_type == 5) ? 4 : 16;
}

ChestInitResult chest_init_with_world(const ChestInitInputs& in) {
    ChestInitResult result;
    result.image.assign(kChestImageSize, 0);

    // Fixture ivars staged before the call (the ARM harness writes the same
    // words into the synthetic instance).
    store_word(result.image, kChestOffsetWorld, in.world_ivar);
    store_word(result.image, kChestOffsetDynamicWorld, in.dynamic_world_ivar);
    store_word(result.image, kChestOffsetPosX, in.pos_x);
    store_word(result.image, kChestOffsetPosY, in.pos_y);
    store_word(result.image, kChestOffsetOwnerID, in.owner_id_ivar);

    // 1. [super initWithWorld:dynamicWorld:saveDict:cache:]
    //    (objc_msgSendSuper2 through GOT slot 0x0105B79C; nil result -> nil)
    result.calls.emplace_back(ChestInitCall::MsgSendSuper, in.self_ptr);
    if (in.super_returns_nil) {
        result.return_value = 0;
        return result;
    }
    result.return_value = in.self_ptr;

    // 2. chestType -> intValue -> Chest.chestType (offset 108)
    result.calls.emplace_back(
        ChestInitCall::ObjectForKeyChestType,
        in.has_chest_type_key ? in.chest_type_box_token : 0u);
    std::int32_t chest_type = in.has_chest_type_key ? in.chest_type_value : 0;
    result.calls.emplace_back(ChestInitCall::IntValueChestType,
                              static_cast<std::uint32_t>(chest_type));
    store_word(result.image, kChestOffsetChestType,
               static_cast<std::uint32_t>(chest_type));

    // 3. chestType == 4 -> 64-byte customRules struct by value. The nil world
    //    path is a 0x40 memset; the non-nil path is objc_msgSend_stret and
    //    only byte 0 of the result is observed.
    if (chest_type == 4) {
        if (in.world_ivar != 0) {
            result.calls.emplace_back(
                ChestInitCall::CustomRulesStret,
                static_cast<std::uint32_t>(in.rules_byte0));
            if (in.rules_byte0 != 0) {
                chest_type = 0;
                store_word(result.image, kChestOffsetChestType, 0);
            }
        } else {
            result.calls.emplace_back(ChestInitCall::CustomRulesMemset, 0x40);
        }
    }

    // 4. ownerID default: [[saveDict objectForKey:@"safeClientID"] retain]
    if (in.owner_id_ivar == 0) {
        result.calls.emplace_back(ChestInitCall::ObjectForKeySafeClientID,
                                  in.safe_client_id_token);
        result.calls.emplace_back(ChestInitCall::RetainSafeClientID,
                                  in.safe_client_id_token);
        store_word(result.image, kChestOffsetOwnerID, in.safe_client_id_token);
    }

    // 5. chestType is RE-READ here: step 3's gate can have zeroed it, in which
    //    case the four-slot branch is not taken and the 16-slot path runs.
    chest_type = static_cast<std::int32_t>(
        load_word(result.image, kChestOffsetChestType));

    if (chest_type == 4) {
        store_word(result.image, kChestOffsetInventoryItems, 0);
    } else {
        result.calls.emplace_back(ChestInitCall::ObjectForKeySaveItemSlots,
                                  in.slots_array_token);
        if (in.slots_array_token != 0) {
            // 5a. [dynamicWorld dynamicWorldChangedAtPos:self->pos
            //                                     objectType:[self objectType]]
            result.calls.emplace_back(ChestInitCall::ObjectType,
                                      in.object_type_value);
            result.calls.emplace_back(ChestInitCall::DynamicWorldChangedAtPos,
                                      in.object_type_value);

            // 5b. [[NSMutableArray alloc] initWithCapacity:numberOfSlots]
            result.calls.emplace_back(ChestInitCall::AllocNSMutableArray,
                                      kChestInventoryArrayToken);
            const int capacity = chest_slot_capacity(chest_type);
            result.calls.emplace_back(ChestInitCall::InitWithCapacity,
                                      static_cast<std::uint32_t>(capacity));
            store_word(result.image, kChestOffsetInventoryItems,
                       kChestInventoryArrayToken);

            // 5c. [slots count] vs numberOfSlots: fewer slots than the chest
            //     can hold -> pad with empty arrays instead of restoring.
            result.calls.emplace_back(
                ChestInitCall::CountSaveItemSlots,
                static_cast<std::uint32_t>(in.slots.size()));
            const int capacity2 = chest_slot_capacity(chest_type);
            if (in.slots.size() < static_cast<std::size_t>(capacity2)) {
                for (int k = 0; k < capacity2; ++k) {
                    const std::uint32_t slot_token =
                        kChestSlotArrayBase + static_cast<std::uint32_t>(k);
                    result.calls.emplace_back(ChestInitCall::ArrayNSMutableArray,
                                              slot_token);
                    result.calls.emplace_back(ChestInitCall::AddObjectSlotArray,
                                              slot_token);
                }
            } else {
                std::uint32_t mutation_counter = 0;
                for (int i = 0; i < capacity2; ++i) {
                    const std::uint32_t slot_token =
                        kChestSlotArrayBase + static_cast<std::uint32_t>(i);
                    result.calls.emplace_back(ChestInitCall::ArrayNSMutableArray,
                                              slot_token);
                    result.calls.emplace_back(ChestInitCall::AddObjectSlotArray,
                                              slot_token);
                    result.calls.emplace_back(ChestInitCall::ObjectAtIndex,
                                              static_cast<std::uint32_t>(i));
                    result.calls.emplace_back(ChestInitCall::StateMemset, 0x20);

                    const ChestSlotEntry& slot =
                        in.slots[static_cast<std::size_t>(i)];
                    std::size_t idx = 0;
                    for (;;) {
                        const std::uint32_t saved = mutation_counter;
                        const std::size_t remaining = slot.items.size() - idx;
                        const std::size_t batch =
                            std::min<std::size_t>(kChestFastEnumerationBatch,
                                                  remaining);
                        result.calls.emplace_back(
                            ChestInitCall::FastEnumeration,
                            static_cast<std::uint32_t>(batch));
                        if (batch == 0) break;

                        for (std::size_t j = 0; j < batch; ++j) {
                            if (mutation_counter != saved) {
                                result.calls.emplace_back(
                                    ChestInitCall::EnumerationMutation,
                                    slot_token);
                            }
                            const ChestSlotItemEntry& e =
                                slot.items[idx + j];
                            // [[InventoryItem alloc] initWithSaveData:itemData]
                            result.calls.emplace_back(
                                ChestInitCall::AllocInventoryItem, e.item_token);
                            if (i == in.mutate_slot &&
                                static_cast<int>(idx + j) == in.mutate_item) {
                                mutation_counter = 1;
                            }
                            result.calls.emplace_back(
                                ChestInitCall::InitWithSaveData, e.item_token);
                            result.calls.emplace_back(
                                ChestInitCall::AutoreleaseItem, e.item_token);
                            // [item itemType] with the itemType != 11 filter
                            result.calls.emplace_back(ChestInitCall::ItemType,
                                                      e.item_type);
                            if (e.item_type != 11) {
                                result.calls.emplace_back(
                                    ChestInitCall::AddObjectItem, e.item_token);
                            }
                        }
                        idx += batch;
                    }
                }
            }
        }
    }

    // 6. Shelf restore loop: runs whenever inventoryItems is still nil
    //    (missing saveItemSlots key, or chestType == 4).
    if (load_word(result.image, kChestOffsetInventoryItems) == 0) {
        for (std::uint32_t m = 0; m < kChestShelfSlotCount; ++m) {
            result.calls.emplace_back(
                ChestInitCall::StringWithFormatShelfRenderItems, m);
            const std::uint32_t render_box = in.shelf_render_box_tokens[m];
            result.calls.emplace_back(
                ChestInitCall::ObjectForKeyShelfRenderItems, render_box);
            const std::uint32_t render_value =
                render_box ? in.shelf_render_values[m] : 0u;
            result.calls.emplace_back(ChestInitCall::IntValueShelfRenderItems,
                                      render_value);
            store_word(result.image,
                       kChestOffsetShelfRenderItems + 4 * m, render_value);

            result.calls.emplace_back(
                ChestInitCall::StringWithFormatShelfItemDataBs, m);
            const std::uint32_t data_box = in.shelf_item_data_box_tokens[m];
            result.calls.emplace_back(
                ChestInitCall::ObjectForKeyShelfItemDataBs, data_box);
            const std::uint32_t data_value =
                data_box ? in.shelf_item_data_values[m] : 0u;
            result.calls.emplace_back(ChestInitCall::IntValueShelfItemDataBs,
                                      data_value);
            store_half(result.image,
                       kChestOffsetShelfItemDataBs + 2 * m,
                       static_cast<std::uint16_t>(data_value));
        }
    }

    // 7. [self initSubDerivedItems] then return self
    result.calls.emplace_back(ChestInitCall::InitSubDerivedItems, 0);

    return result;
}

}  // namespace blockheads::recovered
