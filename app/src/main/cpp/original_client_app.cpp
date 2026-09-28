#include "original_client_app.h"

#include "chest_full.h"
#include "gatherblock_full.h"
#include "kelpvine_full.h"
#include "trainstation_full.h"
#include "npc_full.h"
#include "plant_full.h"
#include "tree_full.h"
#include "workbench_full.h"

#include <array>
#include <fstream>
#include <set>
#include <sstream>

namespace bh176 {
namespace {

constexpr const char* kDynamicIndexHeader =
    "key_hex\tx\ty\tfile\traw_sha256\tbytes";

bool fail(std::string* error, const std::string& message) {
    if (error) *error = message;
    return false;
}

bool parseDecimal(const std::string& text, long long& value) {
    if (text.empty()) return false;
    std::size_t at = 0;
    bool negative = false;
    if (text[at] == '-' || text[at] == '+') {
        negative = text[at] == '-';
        ++at;
    }
    if (at == text.size()) return false;
    long long parsed = 0;
    for (; at < text.size(); ++at) {
        const char c = text[at];
        if (c < '0' || c > '9') return false;
        parsed = parsed * 10 + (c - '0');
    }
    value = negative ? -parsed : parsed;
    return true;
}

bool splitTabs(const std::string& line, std::vector<std::string>& fields) {
    fields.clear();
    std::size_t start = 0;
    for (;;) {
        const auto tab = line.find('\t', start);
        if (tab == std::string::npos) {
            fields.push_back(line.substr(start));
            return true;
        }
        fields.push_back(line.substr(start, tab - start));
        start = tab + 1;
    }
}

std::string jsonEscape(const std::string& text) {
    std::string out;
    for (const char c : text) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\t': out += "\\t"; break;
            default: out += c;
        }
    }
    return out;
}

// Strict record-key grammar (DW_RECORD_KEY_TYPE_EVIDENCE.md). Accepted shapes:
//   <int>_<int>              metadata-only row (no type suffix)
//   <int>_<int>/<digits>     real archive row: the key carries the type id
//   <opaque-without-slash>   prefix not in coordinate form (never typed)
// Everything else (%@/%d, double slash, empty/non-digit suffix, coordinate
// part present with unparseable prefix, non-lowercase/odd key_hex) fails
// open() with the row number instead of being routed by guessing.
struct ParsedRecordKey {
    bool ok = false;
    bool has_coord = false;
    std::int32_t x = 0;
    std::int32_t y = 0;
    bool has_type = false;
    long long type_id = -1;
};

bool parseCoordPrefix(const std::string& text, std::int32_t& x, std::int32_t& y) {
    const auto us = text.find('_');
    if (us == std::string::npos || us == 0 || us + 1 >= text.size() ||
        text.find('_', us + 1) != std::string::npos) {
        return false;
    }
    long long px = 0, py = 0;
    if (!parseDecimal(text.substr(0, us), px) ||
        !parseDecimal(text.substr(us + 1), py)) {
        return false;
    }
    // 32-bit range without relying on <climits> macros being visible
    if (px < -2147483648LL || px > 2147483647LL ||
        py < -2147483648LL || py > 2147483647LL) {
        return false;
    }
    x = static_cast<std::int32_t>(px);
    y = static_cast<std::int32_t>(py);
    return true;
}

ParsedRecordKey parseRecordKeyText(const std::string& text) {
    ParsedRecordKey out;
    if (text.empty() || text.find('\n') != std::string::npos ||
        text.find('\t') != std::string::npos) {
        return out;
    }
    const auto slash = text.find('/');
    const bool has_slash = slash != std::string::npos;
    if (has_slash) {
        if (text.find('/', slash + 1) != std::string::npos) return out;
        const std::string prefix = text.substr(0, slash);
        const std::string suffix = text.substr(slash + 1);
        if (suffix.empty() || suffix.size() > 18) return out;
        for (const char c : suffix) {
            if (c < '0' || c > '9') return out;
        }
        long long parsed = 0;
        if (!parseDecimal(suffix, parsed)) return out;
        if (!parseCoordPrefix(prefix, out.x, out.y)) return out;
        out.has_coord = true;
        out.has_type = true;
        out.type_id = parsed;
    } else {
        out.has_coord = parseCoordPrefix(text, out.x, out.y);
    }
    out.ok = true;
    return out;
}

}  // namespace

bool OriginalClientApp::open(const std::filesystem::path& snapshot_root,
                             std::string* error) {
    // Transactional: everything is parsed and verified into local state; the
    // members (world_, root_, rows_, objects_, report_) are only replaced once
    // every check passes. A failed open() leaves the previous successful
    // state byte-for-byte intact, including the world's block map.
    OriginalClientWorld candidate_world;
    if (!candidate_world.load(snapshot_root, error)) return false;

    const auto index_path = snapshot_root / "dynamic" / "index.tsv";
    std::ifstream index(index_path);
    if (!index) return fail(error, "cannot open dynamic/index.tsv");

    std::string line;
    if (!std::getline(index, line) || line != kDynamicIndexHeader) {
        return fail(error, "invalid dynamic/index.tsv header");
    }

    std::vector<DynamicRecordRow> next_rows;
    std::set<std::string> seen_keys;
    std::size_t line_number = 1;
    while (std::getline(index, line)) {
        ++line_number;
        if (line.empty()) {
            return fail(error, "empty dynamic index row at line " +
                                   std::to_string(line_number));
        }
        std::vector<std::string> fields;
        splitTabs(line, fields);
        if (fields.size() != 6) {
            return fail(error, "dynamic index row has " +
                                   std::to_string(fields.size()) +
                                   " fields at line " + std::to_string(line_number));
        }
        DynamicRecordRow row;
        row.key_hex = fields[0];
        if (row.key_hex.empty()) {
            return fail(error, "empty key_hex at line " + std::to_string(line_number));
        }
        // strict lowercase hex, even length (same discipline as the block index)
        for (const char c : row.key_hex) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return fail(error, "non-hex key at line " + std::to_string(line_number));
            }
        }
        if (row.key_hex.size() % 2 != 0) {
            return fail(error, "odd-length key_hex at line " +
                                   std::to_string(line_number));
        }
        std::string key_text;
        if (!hexDecode(row.key_hex, key_text)) {
            return fail(error, "undecodable key_hex at line " +
                                   std::to_string(line_number));
        }
        const ParsedRecordKey parsed = parseRecordKeyText(key_text);
        if (!parsed.ok) {
            return fail(error, "record key outside the strict grammar at line " +
                                   std::to_string(line_number) + ": " + key_text);
        }
        if (!seen_keys.insert(row.key_hex).second) {
            return fail(error, "duplicate dynamic record key at line " +
                                   std::to_string(line_number) + ": " + key_text);
        }
        row.file = fields[3];
        row.raw_sha256 = fields[4];
        if (!isSha256Hex(row.raw_sha256)) {
            return fail(error, "invalid raw_sha256 at line " +
                                   std::to_string(line_number));
        }
        long long value = 0;
        if (!parseDecimal(fields[5], value) || value < 0) {
            return fail(error, "invalid byte size at line " +
                                   std::to_string(line_number));
        }
        row.bytes = static_cast<std::size_t>(value);
        if (!fields[1].empty() || !fields[2].empty()) {
            long long x = 0, y = 0;
            if (!parseDecimal(fields[1], x) || !parseDecimal(fields[2], y)) {
                return fail(error, "invalid coordinate at line " +
                                       std::to_string(line_number));
            }
            row.x = static_cast<std::int32_t>(x);
            row.y = static_cast<std::int32_t>(y);
            row.has_coordinate = true;
        }
        // coordinate columns must agree with the key's own coordinate part
        if (parsed.has_coord) {
            if (!row.has_coordinate || row.x != parsed.x || row.y != parsed.y) {
                return fail(error, "dynamic index coordinate disagrees with key at line " +
                                       std::to_string(line_number) + ": " + key_text);
            }
        } else if (row.has_coordinate) {
            return fail(error, "dynamic index carries coordinates for a "
                                   "non-coordinate key at line " +
                                   std::to_string(line_number) + ": " + key_text);
        }
        if (row.file.empty() || row.file.front() == '/' ||
            row.file.find("..") != std::string::npos) {
            return fail(error, "unsafe payload path at line " +
                                   std::to_string(line_number));
        }
        // payload path must live under dynamic/ with a declared extension
        {
            const std::filesystem::path rel(row.file);
            if (rel.is_absolute() || rel.filename().empty() ||
                rel.parent_path() != "dynamic" ||
                rel.extension().string().empty()) {
                return fail(error, "payload path outside dynamic/ at line " +
                                       std::to_string(line_number) + ": " + row.file);
            }
        }
        row.key_type_id = parsed.has_type ? parsed.type_id : -1;
        next_rows.push_back(std::move(row));
    }

    // all checks passed: publish the candidate state atomically
    world_.swap(candidate_world);
    root_ = snapshot_root;
    rows_ = std::move(next_rows);
    objects_.clear();
    report_ = ClientAppReport{};
    report_.blocks = world_.blockCount();
    report_.dynamic_records = rows_.size();
    // main-domain (worldv2) worldTime: the saveTime gate's other input. The
    // domain is optional (older snapshots carry no main/); a missing index or
    // record is NOT an error — world_time_ keeps its previous value (0.0 by
    // default), exactly like the b5b harness. Never invented.
    {
        const auto main_index_path = snapshot_root / "main" / "index.tsv";
        std::ifstream main_index(main_index_path);
        std::string main_line;
        if (main_index) {
            std::size_t main_line_number = 0;
            while (std::getline(main_index, main_line)) {
                ++main_line_number;
                if (main_line.empty() || main_line[0] == '#') continue;
                std::array<std::string, 4> main_fields{};
                // 4-field split (key_hex, file, raw_sha256, bytes); a comment
                // or short line simply never matches the worldv2 key below
                {
                    std::istringstream main_fields_stream(main_line);
                    std::string field;
                    std::size_t fi = 0;
                    while (fi < 4 && std::getline(main_fields_stream, field, '\t')) {
                        main_fields[fi++] = field;
                    }
                }
                if (main_fields[0] != "776f726c647632") continue;  // "worldv2"
                const std::filesystem::path worldv2_path =
                    snapshot_root / main_fields[1];
                std::ifstream worldv2_file(worldv2_path, std::ios::binary);
                if (!worldv2_file) break;
                std::string worldv2_raw((std::istreambuf_iterator<char>(worldv2_file)),
                                        std::istreambuf_iterator<char>());
                SaveValue worldv2_plist;
                std::string worldv2_error;
                if (parseXmlPlist(worldv2_raw, worldv2_plist, &worldv2_error)) {
                    const SaveDict worldv2_dict(worldv2_plist);
                    const SaveValue* world_time_value =
                        worldv2_dict.objectForKey("worldTime");
                    if (world_time_value != nullptr) {
                        world_time_ =
                            SaveDict::doubleValue(world_time_value);
                    }
                }
                break;
            }
        }
    }
    return true;
}

void OriginalClientApp::registerRecoveredFactories() {
    // Plant family (batch b5b): every type whose record carries the Plant-level
    // key set (seasonOffset/age/gatherProgress/hasFloweredThisSeason/flowering/
    // frozen/maxAgeGene/growthRateGene/saveTime). TulipPlant 59 additionally
    // reads its own colorGenes/mateColorGenes/mixGenes after the chain; the
    // factory detects those keys itself, so ONE factory serves the family.
    // The registry Factory signature carries no world_time, so the factory
    // closes over this app's worldTime() — the exact [world worldTime] the
    // original passes into loadSaveDictValues's season gate. Re-registering
    // per call is idempotent and picks up a setWorldTime() done after open().
    const double world_time = world_time_;
    const auto make_plant_factory = [world_time](int type_id) {
        return [type_id, world_time](const SaveDict& entry, std::string* error) {
            return plant_full_factory(type_id, entry, world_time, nullptr, error);
        };
    };
    registry_.registerFactory(
        59, make_plant_factory(59),
        "plant full chain (Plant loadSaveDictValues executed",
        ObjectLoadStatus::Recovered);
    // SunflowerPlant 11 / CornPlant 12 / TomatoPlant 62: NO own
    // initWithWorld/loadSaveDictValues in the pinned method map (0 entries
    // each) — they inherit Plant's 0x009559d0 init chain, and their records
    // carry exactly the Plant-level key set (no TulipPlant own keys, no
    // AppleTree availableFood). The factory's Tulip own-key block is
    // presence-gated, so the same chain serves them with tulip.present=false.
    registry_.registerFactory(
        11, make_plant_factory(11),
        "plant full chain (Plant loadSaveDictValues executed",
        ObjectLoadStatus::Recovered);
    registry_.registerFactory(
        12, make_plant_factory(12),
        "plant full chain (Plant loadSaveDictValues executed",
        ObjectLoadStatus::Recovered);
    registry_.registerFactory(
        62, make_plant_factory(62),
        "plant full chain (Plant loadSaveDictValues executed",
        ObjectLoadStatus::Recovered);
    // Crop plants: FlaxPlant 10 / CarrotPlant 27 / ChilliPlant 33 /
    // WheatPlant 61 — the pinned method map carries only constant accessors
    // for them (objectType/plantType/maxAgeBase/...), zero own
    // initWithWorld/loadSaveDictValues/getSaveDict: they inherit Plant's
    // chain exactly like Sunflower/Corn/Tomato (11/12/62).
    registry_.registerFactory(
        10, make_plant_factory(10),
        "plant full chain (Plant loadSaveDictValues executed",
        ObjectLoadStatus::Recovered);
    registry_.registerFactory(
        27, make_plant_factory(27),
        "plant full chain (Plant loadSaveDictValues executed",
        ObjectLoadStatus::Recovered);
    registry_.registerFactory(
        33, make_plant_factory(33),
        "plant full chain (Plant loadSaveDictValues executed",
        ObjectLoadStatus::Recovered);
    registry_.registerFactory(
        61, make_plant_factory(61),
        "plant full chain (Plant loadSaveDictValues executed",
        ObjectLoadStatus::Recovered);
    // NPC family (bucket B): Dodo 13 / Donkey 28 — the executed b3g/b4f
    // chain (DynamicObject base + NPC init + loadValuesFromSaveDict G1-G3
    // + ungated slots). One factory serves the family: the forwarder5
    // bodies contribute no own save keys (zero-own-state readers).
    const auto make_npc_factory = [](int type_id) {
        return [type_id](const SaveDict& entry, std::string* error) {
            return npc_full_factory(type_id, entry, nullptr, error);
        };
    };
    registry_.registerFactory(
        13, make_npc_factory(13), "npc full chain (b3g/b4f executed",
        ObjectLoadStatus::Recovered);
    registry_.registerFactory(
        28, make_npc_factory(28), "npc full chain (b3g/b4f executed",
        ObjectLoadStatus::Recovered);
    // NPC family expansion: the forwarder5 five are word-for-word identical
    // zero-own-state readers (ClownFish 35 / Shark 36 / Scorpion 51 join the
    // already-registered Dodo 13 / DonkeyLike 28), and Yak 63 = the same
    // chain + ownkey5 own keys {milk, hair} (executed; presence-gated).
    registry_.registerFactory(
        35, make_npc_factory(35), "npc full chain (b3g/b4f executed",
        ObjectLoadStatus::Recovered);
    registry_.registerFactory(
        36, make_npc_factory(36), "npc full chain (b3g/b4f executed",
        ObjectLoadStatus::Recovered);
    registry_.registerFactory(
        51, make_npc_factory(51), "npc full chain (b3g/b4f executed",
        ObjectLoadStatus::Recovered);
    registry_.registerFactory(
        63, make_npc_factory(63), "npc full chain (b3g/b4f executed",
        ObjectLoadStatus::Recovered);
    // KelpPlant 34 / VinePlant 58: the executed b4o/b4n twin chains
    // (Plant chain reused via plant_full_load + the mirrored occupied axis).
    const auto make_kelpvine_factory = [world_time](int type_id) {
        return [type_id, world_time](const SaveDict& entry, std::string* error) {
            return kelpvine_full_factory(type_id, entry, world_time, nullptr,
                                         error);
        };
    };
    registry_.registerFactory(
        34, make_kelpvine_factory(34), "kelp chain (b4n executed",
        ObjectLoadStatus::Recovered);
    registry_.registerFactory(
        58, make_kelpvine_factory(58), "vine chain (b4o executed",
        ObjectLoadStatus::Recovered);
    // Chest 46: the b4m executed surface (chestType / safeClientID /
    // saveItemSlots counts / shelf_0..3) + the stated InteractionObject
    // static boundary; item payload decode stays in InventoryItem's domain.
    const auto make_chest_factory = [](int type_id) {
        return [type_id](const SaveDict& entry, std::string* error) {
            return chest_full_factory(type_id, entry, nullptr, error);
        };
    };
    registry_.registerFactory(
        46, make_chest_factory(46), "chest full chain (b4m executed",
        ObjectLoadStatus::Recovered);
    // TrainStation 49: ownkey5 executed own key {text} + the same stated
    // InteractionObject static boundary as Workbench.
    const auto make_trainstation_factory = [](int type_id) {
        return [type_id](const SaveDict& entry, std::string* error) {
            return trainstation_full_factory(type_id, entry, nullptr, error);
        };
    };
    registry_.registerFactory(
        49, make_trainstation_factory(49), "trainstation full chain (ownkey5 executed",
        ObjectLoadStatus::Recovered);
    // GatherBlock 26: base chain + ownkey5 executed own keys
    // {timer@56, lastKnownGatherValue@60} — the full record key set.
    const auto make_gatherblock_factory = [](int type_id) {
        return [type_id](const SaveDict& entry, std::string* error) {
            return gatherblock_full_factory(type_id, entry, nullptr, error);
        };
    };
    registry_.registerFactory(
        26, make_gatherblock_factory(26), "gatherblock full chain (ownkey5 executed",
        ObjectLoadStatus::Recovered);
    // Tree family (bucket A, trees): AppleTree 1 / PineTree 4 / OrangeTree 7.
    // Stage 1 keys are an executed differential (b4d); the gene/growth block
    // is a static decode (b3a) — the factory's reason string states both
    // levels, and saveTime is write-only for trees (no gate, unlike Plant).
    const auto make_tree_factory = [](int type_id) {
        return [type_id](const SaveDict& entry, std::string* error) {
            return tree_full_factory(type_id, entry, nullptr, error);
        };
    };
    registry_.registerFactory(
        1, make_tree_factory(1), "tree full chain (stage1 executed b4d",
        ObjectLoadStatus::Recovered);
    registry_.registerFactory(
        4, make_tree_factory(4), "tree full chain (stage1 executed b4d",
        ObjectLoadStatus::Recovered);
    registry_.registerFactory(
        7, make_tree_factory(7), "tree full chain (stage1 executed b4d",
        ObjectLoadStatus::Recovered);
    // Tree family expansion: CactusTree 5 / CoconutTree 6 / GemTree 57.
    // CoconutTree's own-key set is EMPTY (b3b: super only) — the Tree chain
    // is its whole record. CactusTree and GemTree carry own keys with b3b
    // read-back tables (splitHeightA/B/Direction/availableFood@148 and
    // gemTreeType/fruitYear); the factory captures them presence-gated and
    // the reason names the static evidence level.
    registry_.registerFactory(
        5, make_tree_factory(5), "tree full chain (stage1 executed b4d",
        ObjectLoadStatus::Recovered);
    registry_.registerFactory(
        6, make_tree_factory(6), "tree full chain (stage1 executed b4d",
        ObjectLoadStatus::Recovered);
    registry_.registerFactory(
        57, make_tree_factory(57), "tree full chain (stage1 executed b4d",
        ObjectLoadStatus::Recovered);
    // The five pure trees: the 31-word GetSaveDict pure-forward shape
    // (25-word core sha-gated identical to the registered OrangeTree) and
    // zero own load keys (no own loadSaveDictValues in the pinned map) —
    // see TREEFAMILY9_PURE_TREES.md.
    registry_.registerFactory(
        2, make_tree_factory(2), "tree full chain (stage1 executed b4d",
        ObjectLoadStatus::Recovered);
    registry_.registerFactory(
        3, make_tree_factory(3), "tree full chain (stage1 executed b4d",
        ObjectLoadStatus::Recovered);
    registry_.registerFactory(
        8, make_tree_factory(8), "tree full chain (stage1 executed b4d",
        ObjectLoadStatus::Recovered);
    registry_.registerFactory(
        9, make_tree_factory(9), "tree full chain (stage1 executed b4d",
        ObjectLoadStatus::Recovered);
    registry_.registerFactory(
        37, make_tree_factory(37), "tree full chain (stage1 executed b4d",
        ObjectLoadStatus::Recovered);
    // Workbench (bucket C, the last snapshot stub): the b4q executed
    // differential (16 scalars + lightDict presence); the InteractionObject
    // super keys are static-only and NOT loaded — the reason states both.
    const auto make_workbench_factory = [](int type_id) {
        return [type_id](const SaveDict& entry, std::string* error) {
            return workbench_full_factory(type_id, entry, nullptr, error);
        };
    };
    registry_.registerFactory(
        45, make_workbench_factory(45), "workbench full chain (b4q executed",
        ObjectLoadStatus::Recovered);
}

bool OriginalClientApp::loadDynamicObjects(std::string* error) {
    // the recovered factories must see the CURRENT world_time (settable after
    // open()); register them fresh on every load, right before they run
    registerRecoveredFactories();
    if (rows_.empty() && report_.dynamic_records == 0 &&
        root_.empty()) {
        return fail(error, "open() must run before loadDynamicObjects()");
    }
    objects_.clear();
    report_.dynamic_objects = 0;
    report_.stub_objects = 0;
    report_.recovered_objects = 0;
    report_.verified_objects = 0;
    report_.shared_object_type_objects = 0;
    report_.opaque_records = 0;
    report_.malformed_records = 0;
    report_.unidentified_objects = 0;
    report_.unknown_type_objects = 0;
    report_.out_of_range_objects = 0;
    report_.per_type.clear();
    report_.type_key_used.clear();

    for (const auto& row : rows_) {
        const auto payload_path = root_ / row.file;
        std::ifstream payload(payload_path, std::ios::binary);
        if (!payload) {
            report_.malformed_records++;
            continue;
        }
        std::ostringstream buffer;
        buffer << payload.rdbuf();
        const std::string raw = buffer.str();
        if (row.bytes != 0 && raw.size() != row.bytes) {
            report_.malformed_records++;
            continue;
        }
        // payload digest must equal the index-declared raw_sha256 (validated
        // shape in open()); one byte of corruption is a malformed record,
        // never silently parsed (same contract as the block domain, PR #7).
        if (sha256Hex(raw) != row.raw_sha256) {
            report_.malformed_records++;
            continue;
        }

        SaveValue plist;
        std::string parse_error;
        if (!parseXmlPlist(raw, plist, &parse_error)) {
            // Not a plist (or not the subset we model): counted, never guessed.
            report_.opaque_records++;
            continue;
        }
        const SaveDict dict(plist);
        const SaveValue* objects = dict.objectForKey("dynamicObjects");
        if (SaveDict::count(objects) == 0 && !(objects && objects->isArray())) {
            report_.opaque_records++;
            continue;
        }

        const std::size_t entry_count = SaveDict::count(objects);
        for (std::size_t i = 0; i < entry_count; ++i) {
            const SaveValue* entry = dict.objectAtIndex(objects, i);
            if (entry == nullptr || !entry->isDict()) {
                report_.malformed_records++;
                continue;
            }
            const SaveDict entry_dict(*entry);

            // Type id resolution (batch b5b, strict since PR #7/B). The record
            // key suffix was parsed and validated in open() (row.key_type_id);
            // this is the ONLY typed source. Dictionary objectType /
            // dynamicObjectType remain a fallback solely for rows whose key
            // carries no type suffix (metadata-only snapshot shape); a
            // disagreement is counted, never silently resolved.
            const char* used_key = nullptr;
            long long type_id = -1;
            const long long key_type_id = row.key_type_id;
            if (key_type_id >= 0) {
                type_id = key_type_id;
                used_key = "record_key";
                const SaveValue* dict_type = entry_dict.objectForKey("objectType");
                if (dict_type == nullptr) {
                    dict_type = entry_dict.objectForKey("dynamicObjectType");
                }
                if (dict_type != nullptr &&
                    SaveDict::intValue(dict_type) != key_type_id) {
                    // the two sources disagree: counted, the record key wins
                    report_.type_key_used["type_disagreement"]++;
                }
            } else {
                const SaveValue* type_value = entry_dict.objectForKey("objectType");
                if (type_value == nullptr) {
                    type_value = entry_dict.objectForKey("dynamicObjectType");
                }
                if (type_value == nullptr) {
                    report_.unidentified_objects++;
                    continue;
                }
                type_id = SaveDict::intValue(type_value);
                used_key = entry_dict.objectForKey("objectType") != nullptr
                               ? "objectType"
                               : "dynamicObjectType";
            }
            if (type_id < 1 || type_id > 64) {
                report_.out_of_range_objects++;
                continue;
            }
            // the key that supplied the type of a constructed object; a failed
            // (out-of-range) resolution is counted above, never here
            report_.type_key_used[used_key]++;
            ClientDynamicObject object;
            std::string construct_error;
            if (!registry_.construct(static_cast<int>(type_id), entry_dict,
                                     &object, &construct_error)) {
                report_.unknown_type_objects++;
                continue;
            }
            switch (object.status) {
                case ObjectLoadStatus::Stub: report_.stub_objects++; break;
                case ObjectLoadStatus::Recovered: report_.recovered_objects++; break;
                case ObjectLoadStatus::Verified: report_.verified_objects++; break;
            }
            if (dynamicObjectTypeHasSharedObjectType(object.type_id)) {
                report_.shared_object_type_objects++;
            }
            report_.per_type[object.type_id]++;
            objects_.push_back(std::move(object));
        }
    }

    report_.dynamic_objects = objects_.size();
    save_dict_stub_hits_ = 0;
    return true;
}

std::string OriginalClientApp::toJson() const {
    std::ostringstream out;
    const auto& r = report_;
    out << "{\n";
    out << "  \"blocks\": " << r.blocks << ",\n";
    out << "  \"dynamic_records\": " << r.dynamic_records << ",\n";
    out << "  \"dynamic_objects\": " << r.dynamic_objects << ",\n";
    out << "  \"stub_objects\": " << r.stub_objects << ",\n";
    out << "  \"recovered_objects\": " << r.recovered_objects << ",\n";
    out << "  \"verified_objects\": " << r.verified_objects << ",\n";
    out << "  \"shared_object_type_objects\": " << r.shared_object_type_objects << ",\n";
    out << "  \"opaque_records\": " << r.opaque_records << ",\n";
    out << "  \"malformed_records\": " << r.malformed_records << ",\n";
    out << "  \"unidentified_objects\": " << r.unidentified_objects << ",\n";
    out << "  \"unknown_type_objects\": " << r.unknown_type_objects << ",\n";
    out << "  \"out_of_range_objects\": " << r.out_of_range_objects << ",\n";
    out << "  \"save_dict_stub_hits\": " << save_dict_stub_hits_ << ",\n";
    out << "  \"type_key_used\": {";
    bool first = true;
    for (const auto& entry : r.type_key_used) {
        out << (first ? "" : ", ") << "\"" << jsonEscape(entry.first) << "\": "
            << entry.second;
        first = false;
    }
    out << "},\n";
    out << "  \"per_type\": {";
    first = true;
    for (const auto& entry : r.per_type) {
        out << (first ? "" : ", ") << "\"" << entry.first << "\": "
            << entry.second;
        first = false;
    }
    out << "},\n";
    out << "  \"objects\": [";
    for (std::size_t i = 0; i < objects_.size(); ++i) {
        const auto& object = objects_[i];
        out << (i == 0 ? "\n" : ",\n");
        out << "    {\"type_id\": " << object.type_id
            << ", \"class_name\": \"" << jsonEscape(object.class_name) << "\""
            << ", \"unique_id\": " << object.unique_id
            << ", \"pos_x\": " << object.pos_x
            << ", \"pos_y\": " << object.pos_y;
        if (object.has_float_pos) {
            out << ", \"float_pos_x\": " << object.float_pos_x
                << ", \"float_pos_y\": " << object.float_pos_y;
        }
        out << ", \"status\": \"" << objectLoadStatusName(object.status) << "\""
            << ", \"reason\": \"" << jsonEscape(object.status_reason) << "\"}";
    }
    out << (objects_.empty() ? "]\n" : "\n  ]\n");
    out << "}\n";
    return out.str();
}

}  // namespace bh176
