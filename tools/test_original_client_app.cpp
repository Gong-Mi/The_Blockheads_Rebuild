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
    {
        const auto root = std::filesystem::temp_directory_path() / "bh-original-client-app-test";
        std::filesystem::remove_all(root);
        std::filesystem::create_directories(root / "blocks");
        std::filesystem::create_directories(root / "dynamic");
        writeRaw(root / "blocks/0_0.raw", 17);
        writeText(root / "blocks/index.tsv",
                  "key_hex\tx\ty\tfile\traw_sha256\tbytes\n"
                  "305f30\t0\t0\tblocks/0_0.raw\tdeadbeef\t65541\n");
        writeText(root / "dynamic/record0.plist", kPlistOneObject);
        writeText(root / "dynamic/record1.plist", kPlistNoTypeAndOutOfRange);
        writeText(root / "dynamic/record2.plist", kPlistNotDynamic);
        writeText(root / "dynamic/record3.bin", std::string("\x00\x01\x02binary", 9));
        const std::string dynamic_index =
            "key_hex\tx\ty\tfile\traw_sha256\tbytes\n"
            "305f30\t0\t0\tdynamic/record0.plist\tdeadbeef\t" +
            std::to_string(std::string(kPlistOneObject).size()) + "\n"
            "305f31\t0\t0\tdynamic/record1.plist\tdeadbeef\t" +
            std::to_string(std::string(kPlistNoTypeAndOutOfRange).size()) + "\n"
            "305f32\t0\t0\tdynamic/record2.plist\tdeadbeef\t" +
            std::to_string(std::string(kPlistNotDynamic).size()) + "\n"
            "305f33\t1\t0\tdynamic/record3.bin\tdeadbeef\t9\n";
        writeText(root / "dynamic/index.tsv", dynamic_index);

        bh176::OriginalClientApp app;
        std::string error;
        assert(app.open(root, &error));
        assert(error.empty());
        assert(app.report().blocks == 1);
        assert(app.report().dynamic_records == 4);
        assert(app.world().blockAt(0, 0) != nullptr);

        assert(app.loadDynamicObjects(&error));
        const auto& report = app.report();
        assert(report.dynamic_objects == 2);            // type 1 + type 14
        assert(report.stub_objects == 2);
        assert(report.recovered_objects == 0);
        assert(report.verified_objects == 0);
        assert(report.unidentified_objects == 1);       // entry without a type key
        assert(report.out_of_range_objects == 1);       // objectType 65
        assert(report.opaque_records == 2);             // not-dynamic plist + binary
        assert(report.malformed_records == 0);
        // one valid objectType read + one out-of-range objectType read; one
        // dynamicObjectType override read
        assert(report.type_key_used.at("objectType") == 2);
        assert(report.type_key_used.at("dynamicObjectType") == 1);
        assert(report.per_type.at(1) == 1);
        assert(report.per_type.at(14) == 1);
        assert(report.shared_object_type_objects == 0);

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
        assert(app.report().stub_objects == 1);
        assert(app.report().recovered_objects == 0);

        const std::string json = app.toJson();
        assert(json.find("\"verified_objects\": 1") != std::string::npos);
        assert(json.find("\"per_type\": {\"1\": 1, \"14\": 1}") != std::string::npos);
        assert(json.find("\"class_name\": \"AppleTree\"") != std::string::npos);
        assert(json.find("per-type loader not recovered") != std::string::npos);

        // index-level failures still fail loudly
        writeText(root / "dynamic/index.tsv",
                  "key_hex\tx\ty\tfile\traw_sha256\tbytes\n"
                  "305f30\t0\t0\t../escape.plist\tdeadbeef\t10\n");
        bh176::OriginalClientApp unsafe;
        assert(!unsafe.open(root, &error));
        assert(error.find("unsafe payload path") != std::string::npos);

        writeText(root / "dynamic/index.tsv", "wrong\theader\n");
        bh176::OriginalClientApp broken;
        assert(!broken.open(root, &error));
        assert(error.find("invalid dynamic/index.tsv header") != std::string::npos);

        // a failed re-open must not destroy the previous state
        assert(app.report().blocks == 1);

        std::filesystem::remove_all(root);
    }

    std::cout << "test_original_client_app: PASS\n";
    return 0;
}
