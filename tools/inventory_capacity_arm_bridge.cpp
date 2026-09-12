// Optional ARM differential bridge: synthetic immutable Foundation object graph.
// The real capacity method is executed; this fixture is not the Android runtime.
#define main inventory_capacity_contract_main
#include "test_inventory_capacity.cpp"
#undef main
extern "C" int recovered_capacity_probe(int type, int existingType, unsigned count,
        unsigned a, unsigned b, unsigned existingB, int dragging) {
    Fixture f;
    f.all(f.stack(existingType,count,static_cast<std::uint16_t>(existingB)));
    f.dragging=static_cast<std::int8_t>(dragging);
    return f.run(type,0,static_cast<std::uint16_t>(a),static_cast<std::uint16_t>(b));
}
