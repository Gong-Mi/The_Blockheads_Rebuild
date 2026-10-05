// Recovered model: the PaintMixUI layout (28 ivars, offsets 20..208).
//
// This is the class the live crafting read depends on: the whole live route to a CraftableItem record runs
// World -> UIManager -> paintMixUI, and the record appears at PaintMixUI.workbench once the crafting screen is
// open. Its ivar names are therefore part of the instrument, not just documentation, and this header carries
// them with the offsets and cells the binary declares - re-checked row by row against the ivar table by
// tools/test_paintmixui_layout.py.
//
// The named anchors below are what the live probe watches, and what it reports as null while no crafting
// screen is open (recorded, with the live values, in live_craftable_records.json):
//   workbench@104 incomingCraftableItemObject@112 craftButton@120 countSlider@128
//   currentCount@132 blockhead@108 world@20
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace blockheads::recovered::paint_mix_ui_layout {

struct Field {
    std::size_t offset;
    std::string_view name;
    std::uint32_t cell;
};

inline constexpr std::array<Field, 28> kPaintMixUIFields = {{
    {20, "world", 0x00f3300cU},
    {24, "backgroundShader", 0x00f32fecU},
    {28, "backgroundTexture", 0x00f32ff0U},
    {32, "orthoMatrix", 0x00f32fe4U},
    {96, "windowInfo", 0x00f32fe0U},
    {100, "cache", 0x00f32fe8U},
    {104, "workbench", 0x00f33010U},
    {108, "blockhead", 0x00f3302cU},
    {112, "incomingCraftableItemObject", 0x00f33030U},
    {116, "titleTextView", 0x00f33004U},
    {120, "craftButton", 0x00f33000U},
    {124, "numberCanCraftTextView", 0x00f33028U},
    {128, "countSlider", 0x00f33024U},
    {132, "currentCount", 0x00f33038U},
    {136, "sliderClickDelay", 0x00f33048U},
    {140, "scrollingButtons", 0x00f33008U},
    {152, "upgradeRequiredTextViews", 0x00f33044U},
    {160, "translationOffset", 0x00f3304cU},
    {168, "coloredQuadShader", 0x00f32ff8U},
    {172, "itemsTexture", 0x00f32ff4U},
    {176, "arrowTexture", 0x00f32ffcU},
    {180, "currentColor", 0x00f33034U},
    {184, "previewTextViews", 0x00f33014U},
    {188, "paintingRawTexture", 0x00f33018U},
    {192, "paintingOutputTexture", 0x00f3301cU},
    {196, "paintingOutputImageData", 0x00f33020U},
    {200, "paintingSize", 0x00f3303cU},
    {208, "paintingPreviewSize", 0x00f33040U},
}};

constexpr bool offsetsRise() {
    for (std::size_t i = 1; i < kPaintMixUIFields.size(); ++i)
        if (kPaintMixUIFields[i - 1].offset >= kPaintMixUIFields[i].offset) return false;
    return true;
}
static_assert(offsetsRise(), "the ivar table must be ordered and duplicate-free");

constexpr std::size_t offsetOf(std::string_view want) {
    for (const Field& f : kPaintMixUIFields)
        if (f.name == want) return f.offset;
    return static_cast<std::size_t>(-1);
}

// the anchors the live crafting read watches
static_assert(offsetOf("workbench") == 104);
static_assert(offsetOf("incomingCraftableItemObject") == 112);
static_assert(offsetOf("craftButton") == 120);

}  // namespace blockheads::recovered::paint_mix_ui_layout
