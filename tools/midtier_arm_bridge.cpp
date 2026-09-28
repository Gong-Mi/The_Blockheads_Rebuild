// Optional ARM differential bridge for the mid-tier key-table family
// (tools/test_midtier_arm.py). Uses the module's OWN spec table
// (reconstruction/recovered/midtier_full.h's key/conv/width/offset rows) as
// the single source of truth, so the differential compares the original ARM
// bodies against exactly the decode the production loader carries.
#include "midtier_full.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

const bh176::MidtierKeySpec* specOf(int type_id, const char* key) {
    const bh176::MidtierTypeSpec* spec = bh176::midtierTypeSpec(type_id);
    if (spec == nullptr || spec->keys == nullptr) return nullptr;
    for (std::size_t i = 0; i < spec->key_count; ++i) {
        if (std::strcmp(spec->keys[i].key, key) == 0) return &spec->keys[i];
    }
    return nullptr;
}

const char* convLabel(bh176::MidtierKeySpec::Conv conv) {
    using Conv = bh176::MidtierKeySpec::Conv;
    switch (conv) {
        case Conv::Int: return "int";
        case Conv::Bool: return "bool";
        case Conv::UInt: return "uint";
        case Conv::Float: return "float";
        case Conv::Object: return "retain";
    }
    return "?";
}

std::uint32_t valueOf(const bh176::MidtierKeySpec& key, int index,
                      std::uint32_t token_base) {
    using Conv = bh176::MidtierKeySpec::Conv;
    switch (key.conv) {
        case Conv::Int: return 0x00012345u;   // strh -> 0x2345, strb -> 0x45
        case Conv::Bool: return 1u;
        case Conv::UInt: return 0x0001FFF1u;  // strh -> 0xFFF1
        case Conv::Float: return 0x3FC00000u; // 1.5f
        case Conv::Object: return token_base + static_cast<std::uint32_t>(index) * 0x10u;
    }
    return 0;
}

}  // namespace

extern "C" {

// The class's key names in spec (read) order, comma-joined.
const char* recovered_midtier_key_list(int type_id) {
    static std::string buffer;
    buffer.clear();
    const bh176::MidtierTypeSpec* spec = bh176::midtierTypeSpec(type_id);
    if (spec == nullptr || spec->keys == nullptr) return buffer.c_str();
    for (std::size_t i = 0; i < spec->key_count; ++i) {
        if (i != 0) buffer += ',';
        buffer += spec->keys[i].key;
    }
    return buffer.c_str();
}

// The parent key of a nested read (empty string when the key is a root read).
const char* recovered_midtier_nested_in(int type_id, const char* key) {
    static const char* empty = "";
    const bh176::MidtierKeySpec* spec = specOf(type_id, key);
    return (spec != nullptr && spec->nested_in != nullptr) ? spec->nested_in
                                                           : empty;
}

// case 0: every key present; case 1: even-index keys present; case 2: nil super.
const char* recovered_midtier_sequence(int type_id, int case_id) {
    static std::string buffer;
    buffer = "super";
    if (case_id == 2) {
        // the nil guard returns immediately: the ONLY call is the super one
        // (the return value carries the nil; no further labels exist)
        return buffer.c_str();
    }
    const bh176::MidtierTypeSpec* spec = bh176::midtierTypeSpec(type_id);
    if (spec == nullptr || spec->keys == nullptr) return buffer.c_str();
    for (std::size_t i = 0; i < spec->key_count; ++i) {
        const bh176::MidtierKeySpec& key = spec->keys[i];
        buffer += ",ofk:";
        buffer += key.key;
        buffer += ',';
        buffer += convLabel(key.conv);
        buffer += ':';
        buffer += key.key;
    }
    if (spec->tail_hook != nullptr && spec->tail_hook[0] != '\0') {
        buffer += ",hook";
    }
    return buffer.c_str();
}

// Fills the expected instance image; returns the number of bytes written.
int recovered_midtier_image(int type_id, int case_id, std::uint32_t token_base,
                            unsigned char* out, int n) {
    if (out == nullptr || n <= 0) return -1;
    std::memset(out, 0, static_cast<std::size_t>(n));
    if (case_id == 2) return n;   // nil super: no stores at all
    const bh176::MidtierTypeSpec* spec = bh176::midtierTypeSpec(type_id);
    if (spec == nullptr || spec->keys == nullptr) return -1;
    for (std::size_t i = 0; i < spec->key_count; ++i) {
        const bh176::MidtierKeySpec& key = spec->keys[i];
        bool present = (case_id == 0) || (i % 2 == 0);
        if (present && key.nested_in != nullptr) {
            // a nested key needs its parent present too (nil child => nil read)
            for (std::size_t p = 0; p < spec->key_count; ++p) {
                if (std::strcmp(spec->keys[p].key, key.nested_in) == 0) {
                    const bool parent_present =
                        (case_id == 0) || (p % 2 == 0);
                    present = parent_present;
                    break;
                }
            }
        }
        const std::uint32_t value =
            present ? valueOf(key, static_cast<int>(i), token_base) : 0u;
        if (key.offset < 0 || key.offset + 4 > n) return -2;
        for (int b = 0; b < 4; ++b) {
            const int bytes = (key.width == bh176::MidtierKeySpec::Width::Word)
                                  ? 4
                                  : (key.width == bh176::MidtierKeySpec::Width::Half ? 2 : 1);
            if (b < bytes) {
                out[key.offset + b] =
                    static_cast<unsigned char>((value >> (8 * b)) & 0xFFu);
            }
        }
    }
    return n;
}

}  // extern "C"
