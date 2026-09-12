#include "scroll_inertia.h"
#include <iostream>
#include <cstdlib>
using namespace blockheads::recovered;
void require(bool value, const char* name) {
    if (!value) { std::cerr << "FAIL: " << name << '\n'; std::exit(1); }
}
int main() {
    ScrollState s{false, false, true, {4.0f, 0.0f}};
    auto r = stepInertia(s, false, {10.0f, 2.0f}, 0.125f);
    require(r.writeTranslation, "inertia requests setter");
    require(r.state.velocity.x == 2.0f && r.translation.x == 9.75f && r.translation.y == 2.0f, "decay before movement");
    r = stepInertia(s, true, {10,2}, 0.125f);
    require(!r.state.hasVelocity && !r.writeTranslation && r.state.velocity.x == 4, "goal cancels without decaying");
    s.scrolling = true;
    r = stepInertia(s, true, {10,2}, 0.125f);
    require(r.state.hasVelocity && !r.writeTranslation && r.state.velocity.x == 4, "scroll gate precedes goal");
    s.scrolling = false; s.pinching = true;
    require(!stepInertia(s, false, {10,2}, 0.125f).writeTranslation, "pinch gate");
    s.pinching = false; s.hasVelocity = false;
    require(!stepInertia(s, false, {10,2}, 0.125f).writeTranslation, "inactive inertia");
    s.hasVelocity = true; s.velocity = {0.25f,0};
    r = stepInertia(s, false, {10,2}, 0.0f);
    require(!r.state.hasVelocity && !r.writeTranslation, "squared speed below threshold");
    s.velocity = {0.5f,0};
    require(stepInertia(s,false,{10,2},0).writeTranslation, "squared speed above threshold");
    s.velocity = {4,0};
    r = stepInertia(s,false,{10,2},0.25f);
    require(!r.state.hasVelocity && r.state.velocity.x == 0 && !r.writeTranslation, "zero multiplier");
    r = stepInertia(s,false,{10,2},0.5f);
    require(r.state.velocity.x == -4 && r.translation.x == 12, "do not add invented damping clamp");
    s.velocity = {8,0};
    r = stepInertia(s,false,{0.25f,2},0.125f);
    require(r.translation.x == -0.25f, "do not invent horizontal wrap writeback");
    std::cout << "scroll-inertia: PASS\n";
}
