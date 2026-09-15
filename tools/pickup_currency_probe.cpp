// Differential probe: reads "type a b gate1 gate2 ... gateN" lines on stdin,
// runs the recovered currency region against a trace runtime, prints one
// canonical line per case matching the ARM harness format.
#include "inventory_pickup_currency.h"
#include <cstdio>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace recovered::pickup_currency;

struct Probe final : Runtime {
    std::int32_t type, a, b;
    std::vector<std::int32_t> gates;
    std::size_t i = 0;
    std::vector<std::string> tokens;
    static constexpr Object kSelf = 1, kFree = 2, kItem = 3;

    std::int32_t itemType(Object f) override {
        tokens.push_back(f == kFree ? "itemType@f" : "itemType@?");
        return type;
    }
    void setNeedsRemoved(Object f, std::int8_t v) override {
        char buf[64];
        std::snprintf(buf, sizeof buf, "setNeedsRemoved@f=%d", static_cast<int>(v));
        tokens.push_back(buf);
    }
    std::int32_t dataA(Object f) override {
        tokens.push_back(f == kFree ? "dataA@f" : "dataA@?");
        return a;
    }
    std::int32_t dataB(Object f) override {
        tokens.push_back(f == kFree ? "dataB@f" : "dataB@?");
        return b;
    }
    std::int32_t sendCanPickUp(Object s, std::int32_t d) override {
        tokens.push_back("gate@" + std::to_string(d) + (s == kSelf ? "@s" : "@?"));
        const std::int32_t v = gates[i < gates.size() ? i : gates.size() - 1];
        ++i;
        return v;
    }
    Object allocItem() override {
        tokens.push_back("alloc@I");
        return kItem;
    }
    Object sendInitWithType(Object it, std::int32_t d) override {
        tokens.push_back("init@" + std::to_string(d) + (it == kItem ? "@i" : "@?"));
        return kItem;
    }
    Object sendAutorelease(Object it) override {
        tokens.push_back("autorel@i");
        return it;
    }
    void sendAddItemFlash(Object s, Object) override {
        tokens.push_back(std::string("add@") + (s == kSelf ? "s" : "?"));
    }
};

int main() {
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        std::istringstream in(line);
        Probe p;
        in >> p.type >> p.a >> p.b;
        long g;
        while (in >> g) p.gates.push_back(static_cast<std::int32_t>(g));
        if (p.gates.empty()) p.gates.push_back(1);
        const Outcome o = splitMoney(p, Probe::kSelf, Probe::kFree);
        for (auto& t : p.tokens) std::cout << t << ' ';
        std::cout << "| stop="
                  << (o.stop == Stop::NonMoney ? "nonmoney"
                      : o.stop == Stop::Residual ? "residual" : "zerotail");
        if (o.stop != Stop::NonMoney) {
            std::cout << " P=" << o.platinum << " G=" << o.gold
                      << " C=" << o.copper;
            if (o.stop == Stop::Residual)
                std::cout << " K=" << o.thousands << " R=" << o.remainder;
        }
        std::cout << '\n';
    }
}
