// Replacement-runtime production contracts, NOT original-game crafting parity.
// Generate headers/data outside the repository with tools/process_items.py.
// Link this file, entity_manager.cpp and generated game_recipe_data.cpp using
// -std=c++17 -ffunction-sections -fdata-sections -Wl,--gc-sections and include
// app/src/main/cpp plus the generated directory. No inventory/crafting mocks.
#include "crafting_manager.h"
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <type_traits>

#define CHECK(expr) do { if (!(expr)) { \
    std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expr); std::exit(1); \
} } while (false)

static_assert(std::is_same_v<decltype(&Player::addItem), int (Player::*)(int, int)>);
static_assert(std::is_same_v<decltype(&CraftingManager::update), bool (CraftingManager::*)(float, Player*)>);

static int count(const Player& p, int item) {
    int n = 0;
    for (int i = 0; i < Player::INVENTORY_SIZE; ++i)
        if (p.slots[i] == item) n += p.counts[i];
    return n;
}
static bool sameInventory(const Player& a, const Player& b) {
    for (int i = 0; i < Player::INVENTORY_SIZE; ++i)
        if (a.slots[i] != b.slots[i] || a.counts[i] != b.counts[i]) return false;
    return true;
}
static void fullInventory(Player& p) {
    for (int i = 0; i < Player::INVENTORY_SIZE; ++i) {
        p.slots[i] = ITEM_DIRT;
        p.counts[i] = 99;
    }
}
static void torchIngredients(Player& p, int n = 1) {
    CHECK(p.addItem(ITEM_STICK, n) == n);
    CHECK(p.addItem(ITEM_FLINT, n) == n);
}
static void fullInventoryRetention() {
    Player p;
    CraftingManager crafts;
    torchIngredients(p);
    CHECK(crafts.startCraft(&p, 2, 0, 0));
    fullInventory(p);
    const Player before = p;
    CHECK(!crafts.update(2.0f, &p));
    CHECK(crafts.activeCrafts.size() == 1);
    CHECK(sameInventory(p, before));
    const auto& ac = crafts.activeCrafts.at(0);
    CHECK(ac.progress == 1.0f && ac.finished && ac.remainingOutput == 2);
    for (int i = 0; i < 10; ++i) CHECK(!crafts.update(100.0f, &p));
    CHECK(ac.remainingOutput == 2 && ac.progress == 1.0f);
    CHECK(!crafts.startCraft(&p, 2, 0, 0));
    p.slots[0] = ITEM_EMPTY;
    p.counts[0] = 0;
    CHECK(crafts.update(0.0f, &p));
    CHECK(crafts.activeCrafts.empty());
    CHECK(count(p, ITEM_TORCH) == 2);
    CHECK(!crafts.update(100.0f, &p));
    CHECK(count(p, ITEM_TORCH) == 2);
}
static void normalProgressAndOneShot() {
    Player p;
    CraftingManager crafts;
    torchIngredients(p, 2);
    CHECK(crafts.startCraft(&p, 2, 0, 0));
    CHECK(count(p, ITEM_STICK) == 1 && count(p, ITEM_FLINT) == 1);
    CHECK(!crafts.update(0.0f, &p));
    CHECK(crafts.activeCrafts.at(0).progress == 0.0f);
    CHECK(!crafts.update(0.5f, &p));
    CHECK(crafts.activeCrafts.at(0).progress == 0.25f);
    CHECK(count(p, ITEM_TORCH) == 0);
    CHECK(crafts.update(1.5f, &p));
    CHECK(crafts.activeCrafts.empty());
    CHECK(count(p, ITEM_TORCH) == 2);
    for (int i = 0; i < 10; ++i) CHECK(!crafts.update(2.0f, &p));
    CHECK(count(p, ITEM_TORCH) == 2);
    CHECK(count(p, ITEM_STICK) == 1 && count(p, ITEM_FLINT) == 1);
}
static void partialDeliveryNoDuplication() {
    Player p;
    CraftingManager crafts;
    torchIngredients(p);
    CHECK(crafts.startCraft(&p, 2, 0, 0));
    fullInventory(p);
    p.slots[0] = ITEM_TORCH;
    p.counts[0] = 98;
    CHECK(crafts.update(2.0f, &p));
    CHECK(count(p, ITEM_TORCH) == 99);
    CHECK(crafts.activeCrafts.at(0).remainingOutput == 1);
    const Player before = p;
    for (int i = 0; i < 10; ++i) CHECK(!crafts.update(1.0f, &p));
    CHECK(sameInventory(p, before));
    CHECK(crafts.activeCrafts.at(0).remainingOutput == 1);
    // New materials are not charged during retry, and are not required either.
    p.slots[1] = ITEM_STICK;
    p.counts[1] = 20;
    p.slots[2] = ITEM_FLINT;
    p.counts[2] = 20;
    p.slots[3] = ITEM_EMPTY;
    p.counts[3] = 0;
    CHECK(crafts.update(0.0f, &p));
    CHECK(count(p, ITEM_TORCH) == 100);
    CHECK(count(p, ITEM_STICK) == 20 && count(p, ITEM_FLINT) == 20);
    CHECK(crafts.activeCrafts.empty());
    for (int i = 0; i < 10; ++i) CHECK(!crafts.update(100.0f, &p));
    CHECK(count(p, ITEM_TORCH) == 100);
}
static void invalidTimeAndNull() {
    Player p;
    CraftingManager crafts;
    torchIngredients(p);
    CHECK(!crafts.canCraft(nullptr, 2));
    CHECK(!crafts.startCraft(nullptr, 2, 0, 0));
    CHECK(crafts.activeCrafts.empty());
    CHECK(!crafts.update(1.0f, nullptr));
    CHECK(crafts.startCraft(&p, 2, 0, 0));
    CHECK(!crafts.update(0.5f, &p));
    const Player before = p;
    const float badTimes[] = {-1.0f, std::numeric_limits<float>::quiet_NaN(),
        std::numeric_limits<float>::infinity(), -std::numeric_limits<float>::infinity()};
    for (float dt : badTimes) {
        CHECK(!crafts.update(dt, &p));
        CHECK(crafts.activeCrafts.at(0).progress == 0.25f);
        CHECK(sameInventory(p, before));
    }
    CHECK(!crafts.update(100.0f, nullptr));
    CHECK(crafts.activeCrafts.at(0).progress == 0.25f);
    CHECK(crafts.update(std::numeric_limits<float>::max(), &p));
    CHECK(count(p, ITEM_TORCH) == 2 && crafts.activeCrafts.empty());

    torchIngredients(p);
    CHECK(crafts.startCraft(&p, 2, 0, 0));
    fullInventory(p);
    CHECK(!crafts.update(2.0f, &p));
    p.slots[0] = ITEM_EMPTY;
    p.counts[0] = 0;
    for (float dt : badTimes) CHECK(!crafts.update(dt, &p));
    CHECK(!crafts.update(0.0f, nullptr));
    CHECK(crafts.activeCrafts.at(0).remainingOutput == 2);
    CHECK(count(p, ITEM_TORCH) == 0);
    CHECK(crafts.update(0.0f, &p));
    CHECK(count(p, ITEM_TORCH) == 2);
}
static void insufficientMaterialsNoMutation() {
    Player p;
    CraftingManager crafts;
    CHECK(p.addItem(ITEM_STICK, 4) == 4);
    const Player before = p;
    CHECK(!crafts.canCraft(&p, 2));
    CHECK(!crafts.startCraft(&p, 2, 0, 0));
    CHECK(!crafts.startCraft(&p, -1, 0, 0));
    CHECK(sameInventory(p, before));
    CHECK(crafts.activeCrafts.empty());
}
static void parallelTasksAndBusyBench() {
    Player p;
    CraftingManager crafts;
    torchIngredients(p, 3);
    CHECK(crafts.startCraft(&p, 2, 0, 0));
    const Player before = p;
    CHECK(!crafts.startCraft(&p, 2, 0, 0));
    CHECK(sameInventory(p, before));
    CHECK(crafts.startCraft(&p, 2, 1, 0));
    CHECK(!crafts.update(1.0f, &p));
    CHECK(crafts.activeCrafts.size() == 2);
    for (const auto& entry : crafts.activeCrafts) CHECK(entry.second.progress == 0.5f);
    CHECK(crafts.update(1.0f, &p));
    CHECK(crafts.activeCrafts.empty());
    CHECK(count(p, ITEM_TORCH) == 4);
    CHECK(count(p, ITEM_STICK) == 1 && count(p, ITEM_FLINT) == 1);
}
static void invalidStoredDurationDoesNotDeliver() {
    Player p;
    CraftingManager crafts;
    torchIngredients(p);
    CHECK(crafts.startCraft(&p, 2, 0, 0));
    const float durations[] = {0.0f, -1.0f, std::numeric_limits<float>::quiet_NaN(),
        std::numeric_limits<float>::infinity()};
    for (float duration : durations) {
        crafts.activeCrafts.at(0).totalTime = duration;
        CHECK(!crafts.update(100.0f, &p));
        CHECK(crafts.activeCrafts.at(0).progress == 0.0f);
        CHECK(crafts.activeCrafts.at(0).remainingOutput == 2);
        CHECK(count(p, ITEM_TORCH) == 0);
    }
    crafts.activeCrafts.at(0).totalTime = 2.0f;
    CHECK(crafts.update(2.0f, &p));
    CHECK(count(p, ITEM_TORCH) == 2);
}
int main() {
    const struct { const char* name; void (*run)(); } tests[] = {
        {"full inventory retention/retry", fullInventoryRetention},
        {"normal progress/one shot", normalProgressAndOneShot},
        {"partial delivery/no duplication", partialDeliveryNoDuplication},
        {"invalid dt/null player", invalidTimeAndNull},
        {"insufficient materials/no mutation", insufficientMaterialsNoMutation},
        {"parallel tasks/busy bench", parallelTasksAndBusyBench},
        {"invalid stored duration", invalidStoredDurationDoesNotDeliver},
    };
    for (const auto& test : tests) {
        test.run();
        std::printf("PASS %s\n", test.name);
    }
    std::printf("PASS %zu crafting delivery tests (production runtime)\n", sizeof(tests) / sizeof(tests[0]));
}
