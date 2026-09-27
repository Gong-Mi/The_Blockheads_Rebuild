// Client-app skeleton contract test (batch b5a). Host-only, no ELF needed:
// every fact asserted here comes from the decoded matrix / decoded base loader
// keys, and the stub bookkeeping is checked in both directions (nothing is
// allowed to report "recovered" without an explicit registration).
#include "dynamic_object_registry.h"
#include "original_client_app.h"
#include "original_save_dict.h"
#include "original_save_format.h"

#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {

const char* kPlistOneObject = R"(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//GNUstep//DTD plist 0.9//EN" "http://www.gnustep.org/plist-0_9.dtd">
<plist version="0.9">
<dict>
	<key>dynamicObjects</key>
	<array>
		<dict>
			<key>uniqueID</key>
			<integer>42</integer>
			<key>pos_x</key>
			<integer>3</integer>
			<key>pos_y</key>
			<integer>-7</integer>
			<key>floatPos</key>
			<array>
				<real>1.5</real>
				<real>2.5</real>
			</array>
			<key>objectType</key>
			<integer>1</integer>
		</dict>
	</array>
</dict>
</plist>
)";

const char* kPlistNoTypeAndOutOfRange = R"(<?xml version="1.0"?>
<plist version="1.0">
<dict>
	<key>dynamicObjects</key>
	<array>
		<dict>
			<key>uniqueID</key>
			<integer>7</integer>
		</dict>
		<dict>
			<key>objectType</key>
			<integer>65</integer>
		</dict>
		<dict>
			<key>dynamicObjectType</key>
			<integer>14</integer>
			<key>uniqueID</key>
			<integer>9</integer>
		</dict>
	</array>
</dict>
</plist>
)";

const char* kPlistNotDynamic = R"(<?xml version="1.0"?>
<plist version="1.0">
<dict>
	<key>seed</key>
	<integer>7</integer>
</dict>
</plist>
)";

void writeRaw(const std::filesystem::path& path, std::uint8_t type) {
    std::vector<std::uint8_t> bytes(bh176::kPhysicalBlockPayloadSize, 0);
    bytes[0] = type;
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    assert(out.good());
}

void writeText(const std::filesystem::path& path, const std::string& text) {
    std::ofstream out(path, std::ios::binary);
    out << text;
    assert(out.good());
}

}  // namespace

int main() {
    // ---- SaveDict stub semantics -------------------------------------------------
    {
        bh176::SaveValue value;
        std::string error;
        assert(bh176::parseXmlPlist(kPlistOneObject, value, &error));
        assert(error.empty());
        bh176::SaveDict dict(value);
        const bh176::SaveValue* objects = dict.objectForKey("dynamicObjects");
        assert(objects != nullptr && bh176::SaveDict::count(objects) == 1);
        const bh176::SaveValue* entry = dict.objectAtIndex(objects, 0);
        assert(entry != nullptr);
        const bh176::SaveDict entry_dict(*entry);
        assert(bh176::SaveDict::unsignedLongValue(entry_dict.objectForKey("uniqueID")) == 42ULL);
        assert(bh176::SaveDict::intValue(entry_dict.objectForKey("pos_y")) == -7);
        const bh176::SaveValue* float_pos = entry_dict.objectForKey("floatPos");
        assert(bh176::SaveDict::count(float_pos) == 2);
        assert(bh176::SaveDict::floatValue(entry_dict.objectAtIndex(float_pos, 0)) == 1.5f);
        assert(bh176::SaveDict::floatValue(entry_dict.objectAtIndex(float_pos, 1)) == 2.5f);
        // nil semantics: missing key / out-of-range index are nil, conversions yield 0
        assert(entry_dict.objectForKey("nope") == nullptr);
        assert(entry_dict.objectAtIndex(float_pos, 5) == nullptr);
        assert(bh176::SaveDict::intValue(nullptr) == 0);
        assert(bh176::SaveDict::boolValue(nullptr) == false);
        assert(bh176::SaveDict::count(nullptr) == 0);
        // non-dict receiver yields nil instead of inventing a hit
        bh176::SaveValue scalar;
        scalar.kind = bh176::SaveValue::Kind::Integer;
        scalar.integer = 5;
        const bh176::SaveDict scalar_dict(scalar);
        assert(scalar_dict.objectForKey("dynamicObjects") == nullptr);

        // typed conversions over strings/bools/data/arrays
        const std::string typed = R"(<?xml version="1.0"?>
<plist version="1.0"><dict>
  <key>s</key><string>42abc</string>
  <key>yes</key><string>YES</string>
  <key>nope</key><string>maybe</string>
  <key>t</key><true/>
  <key>blob</key><data>AAEC/w==</data>
</dict></plist>)";
        bh176::SaveValue typed_value;
        assert(bh176::parseXmlPlist(typed, typed_value, &error));
        const bh176::SaveDict typed_dict(typed_value);
        assert(bh176::SaveDict::intValue(typed_dict.objectForKey("s")) == 42);
        assert(bh176::SaveDict::boolValue(typed_dict.objectForKey("yes")) == true);
        assert(bh176::SaveDict::boolValue(typed_dict.objectForKey("nope")) == false);
        assert(bh176::SaveDict::boolValue(typed_dict.objectForKey("t")) == true);
        const bh176::SaveValue* blob = typed_dict.objectForKey("blob");
        assert(blob != nullptr && blob->kind == bh176::SaveValue::Kind::Data);
        assert(blob->text == "000102ff");
        // unsupported value tags are refused instead of guessed
        bh176::SaveValue rejected;
        assert(!bh176::parseXmlPlist("<plist version=\"1.0\"><weird/></plist>", rejected, &error));
        assert(error.find("unsupported plist value tag") != std::string::npos);
        // malformed input is refused
        assert(!bh176::parseXmlPlist("<plist version=\"1.0\"><dict>", rejected, &error));
    }

    // ---- decoded type table ------------------------------------------------------
    {
        std::size_t count = 0;
        const auto* table = bh176::dynamicObjectTypeTable(count);
        assert(count == 64);
        assert(table[0].type_id == 1 && std::string(table[0].class_name) == "AppleTree");
        assert(table[13].type_id == 14 && std::string(table[13].class_name) == "FreeBlock");
        assert(table[24].type_id == 25 && std::string(table[24].class_name) == "DropBear");
        assert(table[63].type_id == 64);
        for (std::size_t i = 0; i < count; ++i) {
            assert(table[i].type_id == static_cast<int>(i) + 1);
            assert(table[i].class_name[0] != '\0');
            assert(table[i].jump_target[0] == '0');
        }
        // the eight classes whose objectType is inherited, not class-constant
        for (const int id : {13, 25, 28, 35, 36, 39, 51, 63}) {
            assert(bh176::dynamicObjectTypeHasSharedObjectType(id));
        }
        assert(!bh176::dynamicObjectTypeHasSharedObjectType(1));
        assert(!bh176::dynamicObjectTypeHasSharedObjectType(14));
    }

    // ---- registry stub / plug-in path -------------------------------------------
    {
        bh176::DynamicObjectRegistry registry;
        for (int id = 1; id <= 64; ++id) {
            assert(registry.statusOf(id) == bh176::ObjectLoadStatus::Stub);
            assert(!registry.hasConcreteFactory(id));
        }
        bh176::SaveValue value;
        std::string error;
        assert(bh176::parseXmlPlist(kPlistOneObject, value, &error));
        const bh176::SaveDict dict(value);
        const bh176::SaveValue* entry =
            dict.objectAtIndex(dict.objectForKey("dynamicObjects"), 0);

        bh176::ClientDynamicObject object;
        assert(registry.construct(1, bh176::SaveDict(*entry), &object, &error));
        assert(object.type_id == 1 && object.class_name == "AppleTree");
        assert(object.unique_id == 42 && object.pos_x == 3 && object.pos_y == -7);
        assert(object.has_float_pos && object.float_pos_x == 1.5f && object.float_pos_y == 2.5f);
        assert(object.status == bh176::ObjectLoadStatus::Stub);
        assert(object.status_reason.find("per-type loader not recovered") != std::string::npos);

        // unknown ids are refused, never guessed
        assert(!registry.construct(0, bh176::SaveDict(*entry), &object, &error));
        assert(!registry.construct(65, bh176::SaveDict(*entry), &object, &error));
        assert(error.find("outside the decoded 1..64 matrix") != std::string::npos);

        // a recovery batch plugs in here; only then does the status change
        registry.registerFactory(
            1,
            [](const bh176::SaveDict& in, std::string* err) {
                if (err) err->clear();
                bh176::ClientDynamicObject custom;
                custom.type_id = 1;
                custom.class_name = "AppleTree";
                custom.unique_id = bh176::SaveDict::unsignedLongValue(in.objectForKey("uniqueID"));
                custom.status = bh176::ObjectLoadStatus::Recovered;
                custom.status_reason = "test factory (b5a plug-in path)";
                return custom;
            },
            "test factory", bh176::ObjectLoadStatus::Recovered);
        assert(registry.hasConcreteFactory(1));
        assert(registry.statusOf(1) == bh176::ObjectLoadStatus::Recovered);
        assert(registry.construct(1, bh176::SaveDict(*entry), &object, &error));
        assert(object.status == bh176::ObjectLoadStatus::Recovered);
        assert(object.status_reason == "test factory (b5a plug-in path)");
    }

    // ---- app pipeline over a synthetic snapshot ----------------------------------
    // Strict contract (post PR #7): every dynamic index row needs a 64-hex
    // raw_sha256 that matches its payload, coordinates must agree with the key,
    // and a failed open() must leave the previous state untouched.
    {
        const auto root = std::filesystem::temp_directory_path() / "bh-original-client-app-test";
        std::filesystem::remove_all(root);
        std::filesystem::create_directories(root / "blocks");
        std::filesystem::create_directories(root / "dynamic");
        writeRaw(root / "blocks/0_0.raw", 17);
        writeText(root / "blocks/index.tsv",
                  "key_hex\tx\ty\tfile\traw_sha256\tbytes\n"
                  "305f30\t0\t0\tblocks/0_0.raw\ta6587fb969b02057e178d1621397b304fb0b42e0c205122bf52649537e9a0d65\t65541\n");
        const std::string kRecordTyped = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>21</integer><key>pos_x</key><integer>5</integer><key>pos_y</key><integer>-2</integer></dict>
</array></dict></plist>
)";
        writeText(root / "dynamic/record0.plist", kPlistOneObject);
        writeText(root / "dynamic/record1.plist", kPlistNoTypeAndOutOfRange);
        writeText(root / "dynamic/record4.plist", kRecordTyped);
        writeText(root / "dynamic/record2.plist", kPlistNotDynamic);
        writeText(root / "dynamic/record3.bin", std::string("\x00\x01\x02binary", 9));
        const std::string dynamic_index =
            "key_hex\tx\ty\tfile\traw_sha256\tbytes\n"
            // metadata-only key: fallback to the per-object objectType
            "305f30\t0\t0\tdynamic/record0.plist\t" + bh176::sha256Hex(kPlistOneObject) + "\t" +
            std::to_string(std::string(kPlistOneObject).size()) + "\n"
            // metadata-only key: unidentified + out-of-range + dynamicObjectType
            "305f31\t0\t1\tdynamic/record1.plist\t" + bh176::sha256Hex(kPlistNoTypeAndOutOfRange) + "\t" +
            std::to_string(std::string(kPlistNoTypeAndOutOfRange).size()) + "\n"
            // real-archive key with type suffix: record_key is the typed source
            "325f302f39\t2\t0\tdynamic/record4.plist\t" + bh176::sha256Hex(kRecordTyped) + "\t" +
            std::to_string(std::string(kRecordTyped).size()) + "\n"
            // opaque shapes (valid digests so they reach the plist stage)
            "335f30\t3\t0\tdynamic/record2.plist\t" + bh176::sha256Hex(kPlistNotDynamic) + "\t" +
            std::to_string(std::string(kPlistNotDynamic).size()) + "\n"
            "305f33\t0\t3\tdynamic/record3.bin\t" +
            bh176::sha256Hex(std::string("\x00\x01\x02binary", 9)) + "\t9\n";
        writeText(root / "dynamic/index.tsv", dynamic_index);

        bh176::OriginalClientApp app;
        std::string error;
        assert(app.open(root, &error));
        assert(error.empty());
        assert(app.report().blocks == 1);
        assert(app.report().dynamic_records == 5);
        assert(app.world().blockAt(0, 0) != nullptr);

        assert(app.loadDynamicObjects(&error));
        {
            const auto& report = app.report();
            assert(report.dynamic_objects == 3);            // type 1 + type 14 + type 9
            assert(report.stub_objects == 3);
            assert(report.recovered_objects == 0);
            assert(report.verified_objects == 0);
            assert(report.unidentified_objects == 1);       // entry without a type key
            assert(report.out_of_range_objects == 1);       // objectType 65
            assert(report.opaque_records == 2);             // not-dynamic plist + binary
            assert(report.malformed_records == 0);
            assert(report.type_key_used.at("objectType") == 1);
            assert(report.type_key_used.at("dynamicObjectType") == 1);
            assert(report.type_key_used.at("record_key") == 1);
            assert(report.per_type.at(1) == 1);
            assert(report.per_type.at(14) == 1);
            assert(report.per_type.at(9) == 1);
            assert(report.shared_object_type_objects == 0);
        }

        // second pass with one type plugged in: status follows the registration
        app.registry().registerFactory(
            1,
            [](const bh176::SaveDict& in, std::string* err) {
                if (err) err->clear();
                auto object = bh176::DynamicObjectRegistry::baseStub(
                    1, in);
                object.status = bh176::ObjectLoadStatus::Verified;
                object.status_reason = "test verified factory";
                return object;
            },
            "verified test factory", bh176::ObjectLoadStatus::Verified);
        assert(app.loadDynamicObjects(&error));
        assert(app.report().verified_objects == 1);
        assert(app.report().stub_objects == 2);
        assert(app.report().recovered_objects == 0);

        const std::string json = app.toJson();
        assert(json.find("\"verified_objects\": 1") != std::string::npos);
        assert(json.find("\"class_name\": \"AppleTree\"") != std::string::npos);
        assert(json.find("per-type loader not recovered") != std::string::npos);

        // ---- recovered-factory registration (production path, plant family) --
        // loadDynamicObjects() registers the b5b plant chain on every load:
        // a TulipPlant-typed record (type 59) must come back Recovered through
        // the same production registration the JNI/CLI paths use, not through
        // a hand-rolled factory. The original fixture carries no type-59 row,
        // so this swaps in a minimal two-row index (AppleTree + TulipPlant).
        {
            const std::string kTulipRecord = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>91</integer><key>pos_x</key><integer>4</integer><key>pos_y</key><integer>2</integer><key>seasonOffset</key><integer>3</integer><key>maxAgeGene</key><integer>200</integer><key>saveTime</key><real>100.0</real><key>colorGenes</key><integer>13364</integer></dict>
</array></dict></plist>
)";
            writeText(root / "dynamic/record5.plist", kTulipRecord);
            const std::string tulip_index =
                "key_hex\tx\ty\tfile\traw_sha256\tbytes\n" +
                std::string("305f30\t0\t0\tdynamic/record0.plist\t") +
                bh176::sha256Hex(kPlistOneObject) + "\t" +
                std::to_string(std::string(kPlistOneObject).size()) + "\n" +
                "345f322f3539\t4\t2\tdynamic/record5.plist\t" +
                bh176::sha256Hex(kTulipRecord) + "\t" +
                std::to_string(std::string(kTulipRecord).size()) + "\n";
            writeText(root / "dynamic/index.tsv", tulip_index);
            assert(app.open(root, &error));
            app.setWorldTime(100.0);   // gate must NOT fire (100-100 < 1800)
            assert(app.loadDynamicObjects(&error));
            assert(app.report().dynamic_objects == 2);
            assert(app.report().recovered_objects == 1);  // the TulipPlant
            // the AppleTree row runs through this app's earlier Verified
            // factory for type 1 (still registered; registerRecoveredFactories
            // only adds the plant chain), so it counts as verified, not stub
            assert(app.report().verified_objects == 1);
            assert(app.report().stub_objects == 0);
            bool saw_tulip = false;
            for (const auto& object : app.objects()) {
                if (object.type_id == 59) {
                    saw_tulip = true;
                    assert(object.status == bh176::ObjectLoadStatus::Recovered);
                    assert(object.class_name == "TulipPlant");
                    assert(object.unique_id == 91);
                    assert(object.status_reason.find("plant full chain") !=
                           std::string::npos);
                }
            }
            assert(saw_tulip);
            // the season gate: with world_time far past saveTime the chain still
            // returns Recovered; the gate only clears hasFloweredThisSeason
            app.setWorldTime(99999.0);
            assert(app.loadDynamicObjects(&error));
            assert(app.report().recovered_objects == 1);
        }

        // ---- Plant-family inheritance types (11/12/62) ---------------------
        // SunflowerPlant/CornPlant/TomatoPlant have NO own loader in the
        // pinned method map (they inherit Plant's init chain); their records
        // carry the Plant-level key set only. The same production factory
        // must serve them with the Tulip own-key block closed.
        {
            const std::string kPlantRecord = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>80</integer><key>pos_x</key><integer>181</integer><key>pos_y</key><integer>531</integer><key>seasonOffset</key><integer>9</integer><key>maxAgeGene</key><integer>153</integer><key>growthRateGene</key><integer>168</integer><key>saveTime</key><real>900.0</real><key>availableFood</key><real>951.95</real></dict>
</array></dict></plist>
)";
            writeText(root / "dynamic/record6.plist", kPlantRecord);
            // key 9_6/11 (hex of "9_6/11"): typed record key, type 11
            const std::string plant_index =
                "key_hex\tx\ty\tfile\traw_sha256\tbytes\n" +
                std::string("395f362f3131\t9\t6\tdynamic/record6.plist\t") +
                bh176::sha256Hex(kPlantRecord) + "\t" +
                std::to_string(std::string(kPlantRecord).size()) + "\n";
            writeText(root / "dynamic/index.tsv", plant_index);
            bh176::OriginalClientApp plant_app;
            assert(plant_app.open(root, &error));
            plant_app.setWorldTime(900.0);
            assert(plant_app.loadDynamicObjects(&error));
            assert(plant_app.report().dynamic_objects == 1);
            assert(plant_app.report().recovered_objects == 1);
            const auto& object = plant_app.objects().at(0);
            assert(object.type_id == 11);
            assert(object.class_name == "SunflowerPlant");
            assert(object.unique_id == 80);
            assert(object.status == bh176::ObjectLoadStatus::Recovered);
            assert(object.status_reason.find("plant full chain") !=
                   std::string::npos);
        }

        // ---- strict grammar controls: every row problem fails open() loudly ----
        const std::string good_index = dynamic_index;
        struct BadCase {
            std::string row;
            const char* expect;
        };
        const std::string k64hex = bh176::sha256Hex("x");
        const std::string kPfx = "\t0\t0\tdynamic/record0.plist\t" + k64hex + "\t1\n";
        const std::vector<BadCase> bad_cases = {
            {"41FF41", "non-hex key"},
            {"305f302", "odd-length key_hex"},
            {"25402f2564", "record key outside the strict grammar"},       // %@/%d
            {"305f302f353978", "record key outside the strict grammar"},   // 0_0/59x
            {"305f30\t7\t7\tdynamic/record0.plist\t" + k64hex + "\t1\n",
             "coordinate disagrees with key"},
            {"414243\t0\t0\tdynamic/record0.plist\t" + k64hex + "\t1\n",
             "coordinates for a non-coordinate key"},                       // "ABC"
        };
        for (const auto& bad : bad_cases) {
            std::string row = bad.row;
            if (row.size() < 20) row += kPfx;   // short hexes get the standard tail
            const std::string index_text =
                "key_hex\tx\ty\tfile\traw_sha256\tbytes\n" + row;
            writeText(root / "dynamic/index.tsv", index_text);
            bh176::OriginalClientApp probe;
            assert(!probe.open(root, &error));
            assert(error.find(bad.expect) != std::string::npos);
        }
        // duplicate keys must be refused
        {
            const std::string row = "305f30" + kPfx;
            writeText(root / "dynamic/index.tsv",
                      "key_hex\tx\ty\tfile\traw_sha256\tbytes\n" + row + row);
            bh176::OriginalClientApp probe;
            assert(!probe.open(root, &error));
            assert(error.find("duplicate dynamic record key") != std::string::npos);
        }

        // ---- transactional contract: a failed re-open keeps every member ----
        // state as the last successful load left it (world, rows, objects,
        // report, root). Current state: the two-row AppleTree+Tulip index
        // from the recovered-factory block above (1 verified + 1 recovered).
        assert(app.report().blocks == 1);
        assert(app.objects().size() == 2);
        assert(app.root() == root);
        writeText(root / "dynamic/index.tsv", "wrong\theader\n");
        bh176::OriginalClientApp broken;
        assert(!broken.open(root, &error));
        assert(error.find("invalid dynamic/index.tsv header") != std::string::npos);
        assert(app.report().blocks == 1);
        assert(app.objects().size() == 2);
        assert(app.root() == root);
        // the same failure against an ALREADY-loaded instance: members intact
        assert(!app.open(root, &error));
        assert(app.report().blocks == 1 && app.report().dynamic_records == 2);
        assert(app.objects().size() == 2);

        // escape path with an otherwise-valid shape must fail on path safety
        writeText(root / "dynamic/index.tsv",
                  "key_hex\tx\ty\tfile\traw_sha256\tbytes\n"
                  "305f30\t0\t0\t../escape.plist\t" + k64hex + "\t10\n");
        bh176::OriginalClientApp unsafe;
        assert(!unsafe.open(root, &error));
        assert(error.find("unsafe payload path") != std::string::npos);

        // payload corruption after a valid open(): digest mismatch is malformed,
        // never a silently parsed record
        writeText(root / "dynamic/index.tsv", good_index);
        assert(app.open(root, &error));
        assert(app.loadDynamicObjects(&error));
        const std::size_t baseline_malformed = app.report().malformed_records;
        writeText(root / "dynamic/record4.plist", kRecordTyped + "<!-- tampered -->");
        assert(app.open(root, &error));
        assert(app.loadDynamicObjects(&error));
        assert(app.report().malformed_records == baseline_malformed + 1);
        assert(app.report().per_type.count(9) == 0);

        std::filesystem::remove_all(root);
    }

    std::cout << "test_original_client_app: PASS\n";
    return 0;
}
