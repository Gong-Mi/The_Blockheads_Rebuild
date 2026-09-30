// Entry-only differential bridge. Reuses synthetic fixture, not Foundation.
#define main pickup_fixture_main
#include "test_inventory_pickup.cpp"
#undef main

int main() {
    int dragging, a, b, intentional, ignoring, meditating, priority;
    while (std::cin >> dragging >> a >> b >> intentional >> ignoring >> meditating >> priority) {
        Fixture f;
        f.dragging = static_cast<std::int8_t>(dragging);
        f.gateA = static_cast<std::int8_t>(a);
        f.gateB = static_cast<std::int8_t>(b);
        f.ignoring = static_cast<std::int8_t>(ignoring);
        f.meditatingFlag = static_cast<std::int8_t>(meditating);
        f.priority = priority == 1 ? f.self : priority == 2 ? 99 : 0;
        f.run(static_cast<std::int8_t>(intentional));
        bool allowed = false;
        for (const auto& event : f.events) if (event == "itemType") allowed = true;
        std::cout << (allowed ? 1 : 0);
        for (const auto& event : f.events) {
            if (event == "itemType") break;
            if (event == "dragging" || event == "gateA" || event == "gateB" ||
                event == "priority" || event == "ignoring" || event == "meditating")
                std::cout << ' ' << event;
        }
        std::cout << '\n';
    }
}
