#include "original_client_app.h"

#include <array>
#include <fstream>
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

}  // namespace

bool OriginalClientApp::open(const std::filesystem::path& snapshot_root,
                             std::string* error) {
    if (!world_.load(snapshot_root, error)) return false;

    const auto index_path = snapshot_root / "dynamic" / "index.tsv";
    std::ifstream index(index_path);
    if (!index) return fail(error, "cannot open dynamic/index.tsv");

    std::string line;
    if (!std::getline(index, line) || line != kDynamicIndexHeader) {
        return fail(error, "invalid dynamic/index.tsv header");
    }

    std::vector<DynamicRecordRow> next_rows;
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
        row.file = fields[3];
        row.raw_sha256 = fields[4];
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
        if (row.file.empty() || row.file.front() == '/' ||
            row.file.find("..") != std::string::npos) {
            return fail(error, "unsafe payload path at line " +
                                   std::to_string(line_number));
        }
        next_rows.push_back(std::move(row));
    }

    root_ = snapshot_root;
    rows_ = std::move(next_rows);
    objects_.clear();
    report_ = ClientAppReport{};
    report_.blocks = world_.blockCount();
    report_.dynamic_records = rows_.size();
    return true;
}

bool OriginalClientApp::loadDynamicObjects(std::string* error) {
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

            const char* used_key = nullptr;
            const SaveValue* type_value = entry_dict.objectForKey("objectType");
            if (type_value != nullptr) used_key = "objectType";
            if (type_value == nullptr) {
                type_value = entry_dict.objectForKey("dynamicObjectType");
                if (type_value != nullptr) used_key = "dynamicObjectType";
            }
            if (type_value == nullptr) {
                report_.unidentified_objects++;
                continue;
            }
            report_.type_key_used[used_key]++;
            const long long type_id = SaveDict::intValue(type_value);
            if (type_id < 1 || type_id > 64) {
                report_.out_of_range_objects++;
                continue;
            }
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
