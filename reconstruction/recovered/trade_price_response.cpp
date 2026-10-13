#include "trade_price_response.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the trade-price-response family (E108).
namespace blockheads::recovered {
namespace {

static_assert(kPriceEpsilon == 0.01f, "policy epsilon (pools 0x5cd708/710)");
static_assert(kPriceDecayBase == 0.999, "decay base (pool 0x5cd718)");

}  // namespace
}  // namespace blockheads::recovered
