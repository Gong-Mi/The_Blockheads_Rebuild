// plant_full batch b5b: unit + integration contract.
// Unit: one real-shape TulipPlant record dict -> full state via the
// recovered chain (base + Plant loadSaveDictValues + Tulip keys).
// Integration: the record-key type dispatch in OriginalClientApp — a
// snapshot whose objects carry NO objectType (the real archive's shape)
// must now construct all its objects with per-type histograms.
#include "../../reconstruction/recovered/plant_full.h"
#include "../../app/src/main/cpp/original_client_app.h"
#include "../../app/src/main/cpp/original_save_format.h"

#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

namespace {

const char* kTulipPlist = R"(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//GNUstep//DTD plist 0.9//EN" "http://www.gnustep.org/plist-0_9.dtd">
<plist version="0.9">
<dict>
	<key>dynamicObjects</key>
	<array>
		<dict>
			<key>age</key><real>12.5</real>
			<key>availableFood</key><real>3.25</real>
			<key>colorGenes</key><integer>200</integer>
			<key>floatPos</key><array><real>1.5</real><real>2.5</real></array>
			<key>frozen</key><false/>
			<key>gatherProgress</key><integer>7</integer>
			<key>growthRateGene</key><integer>300</integer>
			<key>hasFloweredThisSeason</key><true/>
			<key>mateColorGenes</key><integer>150</integer>
			<key>maxAgeGene</key><integer>90</integer>
			<key>mixGenes</key><integer>180</integer>
			<key>pos_x</key><integer>5</integer>
			<key>pos_y</key><integer>16</integer>
			<key>saveTime</key><real>1000.0</real>
			<key>seasonOffset</key><integer>3</integer>
			<key>uniqueID</key><integer>77</integer>
		</dict>
	</array>
</dict>
</plist>
)";

void writeText(const std::filesystem::path& path, const std::string& text) {
    std::ofstream out(path, std::ios::binary);
    out << text;
    assert(out.good());
}

void writeRaw(const std::filesystem::path& path, std::uint8_t type) {
    std::string bytes(bh176::kPhysicalBlockPayloadSize, '\0');
    bytes[0] = static_cast<char>(type);
    std::ofstream out(path, std::ios::binary);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    assert(out.good());
}

}  // namespace

int main() {
    bh176::SaveValue parsed;
    std::string error;
    assert(bh176::parseXmlPlist(kTulipPlist, parsed, &error));
    const bh176::SaveDict dict(parsed);
    const bh176::SaveValue* objects = dict.objectForKey("dynamicObjects");
    assert(bh176::SaveDict::count(objects) == 1);
    const bh176::SaveDict entry(*dict.objectAtIndex(objects, 0));

    // ---- unit: full state through the recovered chain -----------------------
    {
        // world_time - save_time > 1800 -> the season gate must clear the flag
        bh176::PlantFullState state =
            bh176::plant_full_load({entry, /*world_time=*/5000.0});
        assert(state.unique_id == 77);
        assert(state.pos_x == 5 && state.pos_y == 16);
        assert(state.has_float_pos && state.float_pos_x == 1.5f &&
               state.float_pos_y == 2.5f);
        assert(state.season_offset == 3);
        assert(state.age == 12.5f);
        assert(state.gather_progress == 7);
        assert(state.has_flowered == false);  // cleared by the 1800s gate
        assert(state.season_gate_fired);
        assert(state.frozen == false);
        assert(state.max_age_gene == 90);
        assert(state.growth_rate_gene == 255);  // 300 clamped via strh+helper

        // below the gate the saved flag survives
        bh176::PlantFullState fresh =
            bh176::plant_full_load({entry, /*world_time=*/2000.0});
        assert(fresh.has_flowered == true);
        assert(!fresh.season_gate_fired);

        // TulipPlant own keys
        assert(state.tulip.present);
        assert(state.tulip.available_food == 3.25f);
        assert(state.tulip.color_genes == 200);
        assert(state.tulip.mate_color_genes == 150);
        assert(state.tulip.mix_genes == 180);

        // the factory runs the recovered chain for real and hands the state out
        std::string factory_error;
        bh176::PlantFullState factory_state;
        bh176::ClientDynamicObject object = bh176::plant_full_factory(
            59, entry, 5000.0, &factory_state, &factory_error);
        assert(factory_error.empty());
        assert(object.type_id == 59);
        assert(object.class_name == "TulipPlant");
        assert(object.unique_id == 77);
        assert(object.status == bh176::ObjectLoadStatus::Recovered);
        assert(factory_state.unique_id == 77);
        assert(factory_state.has_flowered == false);  // the gate ran inside
        assert(factory_state.season_gate_fired);
        assert(factory_state.tulip.mix_genes == 180);
        // below the gate the factory keeps the saved flag too
        bh176::PlantFullState fresh_state;
        bh176::plant_full_factory(59, entry, 2000.0, &fresh_state,
                                  &factory_error);
        assert(fresh_state.has_flowered == true && !fresh_state.season_gate_fired);
        // a null out_state is allowed (the registry Factory signature path)
        bh176::plant_full_factory(59, entry, 0.0, nullptr, &factory_error);
        assert(factory_error.empty());
    }

    // ---- integration: record-key type dispatch over a real-shape snapshot --
    {
        const auto root = std::filesystem::temp_directory_path() /
                           "bh-plant-full-record-key-test";
        std::filesystem::remove_all(root);
        std::filesystem::create_directories(root / "blocks");
        std::filesystem::create_directories(root / "dynamic");
        writeRaw(root / "blocks/5_16.raw", 3);
        // sha256 of the 65,541-byte payload (type 3 + zero fill); the loader
        // verifies it (PR #7 4fd056c).
        writeText(root / "blocks/index.tsv",
                  "key_hex\tx\ty\tfile\traw_sha256\tbytes\n"
                  "355f3136\t5\t16\tblocks/5_16.raw\tdf881221efb4dab14580a52cdb414aac8d45b6398c9db3dc70276984993fa9b0\t65541\n");
        writeText(root / "dynamic/record0.plist", kTulipPlist);
        // key 5_16/59 (hex of "5_16/59"): NO objectType in the dictionaries
        writeText(root / "dynamic/index.tsv",
                  "key_hex\tx\ty\tfile\traw_sha256\tbytes\n"
                  "355f31362f3539\t5\t16\tdynamic/record0.plist\tdeadbeef\t" +
                      std::to_string(std::string(kTulipPlist).size()) + "\n");

        bh176::OriginalClientApp app;
        assert(app.open(root, &error));
        assert(app.report().blocks == 1);
        assert(app.loadDynamicObjects(&error));
        const auto& report = app.report();
        assert(report.dynamic_records == 1);
        assert(report.dynamic_objects == 1);
        assert(report.unidentified_objects == 0);  // the b5a gap is closed
        assert(report.type_key_used.at("record_key") == 1);
        assert(report.per_type.at(59) == 1);
        // the record-key type routes to the registered Plant factory
        app.registry().registerFactory(
            59,
            [](const bh176::SaveDict& in, std::string* err) {
                return bh176::plant_full_factory(59, in, 0.0, nullptr, err);
            },
            "plant full chain", bh176::ObjectLoadStatus::Recovered);
        assert(app.loadDynamicObjects(&error));
        assert(app.report().recovered_objects == 1);
        assert(app.report().stub_objects == 0);
        const auto& object = app.objects().at(0);
        assert(object.class_name == "TulipPlant");
        assert(object.unique_id == 77);
        assert(object.float_pos_x == 1.5f);

        // disagreement control: an objectType that contradicts the record key
        // is counted, not silently resolved (the record key still wins routing)
        std::string disagreement = kTulipPlist;
        const std::string marker = "<key>uniqueID</key>";
        disagreement.replace(disagreement.find(marker), marker.size(),
                             "<key>objectType</key><integer>14</integer>"
                             "<key>uniqueID</key>");
        writeText(root / "dynamic/record0.plist", disagreement);
        writeText(root / "dynamic/index.tsv",
                  "key_hex\tx\ty\tfile\traw_sha256\tbytes\n"
                  "355f31362f3539\t5\t16\tdynamic/record0.plist\tdeadbeef\t" +
                      std::to_string(disagreement.size()) + "\n");
        assert(app.open(root, &error));  // re-open: the index carries new sizes
        assert(app.loadDynamicObjects(&error));
        const auto it = app.report().type_key_used.find("type_disagreement");
        assert(it != app.report().type_key_used.end() && it->second == 1);
        assert(app.report().per_type.at(59) == 1);  // record key is primary
        std::filesystem::remove_all(root);
    }

    std::cout << "test_plant_full: PASS\n";
    return 0;
}
