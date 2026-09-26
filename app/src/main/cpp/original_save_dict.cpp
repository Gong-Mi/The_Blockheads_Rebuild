#include "original_save_dict.h"

#include <cctype>
#include <cerrno>
#include <cstdlib>

namespace bh176 {
namespace {

struct Parser {
    const std::string& xml;
    std::size_t at = 0;
    std::string* error;

    bool fail(const std::string& message) {
        if (error) *error = message + " at offset " + std::to_string(at);
        return false;
    }

    void skipProlog() {
        for (;;) {
            while (at < xml.size() && std::isspace(static_cast<unsigned char>(xml[at]))) ++at;
            if (xml.compare(at, 5, "<?xml") == 0 || xml.compare(at, 2, "<?") == 0) {
                const auto end = xml.find("?>", at);
                at = end == std::string::npos ? xml.size() : end + 2;
                continue;
            }
            if (xml.compare(at, 9, "<!DOCTYPE") == 0) {
                const auto end = xml.find('>', at);
                at = end == std::string::npos ? xml.size() : end + 1;
                continue;
            }
            if (xml.compare(at, 4, "<!--") == 0) {
                const auto end = xml.find("-->", at);
                at = end == std::string::npos ? xml.size() : end + 3;
                continue;
            }
            return;
        }
    }

    // Reads "<tag ...>" and reports the tag name; consumes nothing on failure.
    bool openTag(std::string& name) {
        skipProlog();
        if (at >= xml.size() || xml[at] != '<') {
            fail("expected a tag");
            return false;
        }
        ++at;
        std::string prefix;
        if (at < xml.size() && xml[at] == '/') {
            prefix = "/";   // closing tag: name carries the marker
            ++at;
        }
        const auto start = at;
        while (at < xml.size() && !std::isspace(static_cast<unsigned char>(xml[at])) &&
               xml[at] != '>' && xml[at] != '/') {
            ++at;
        }
        name = prefix + xml.substr(start, at - start);
        const auto close = xml.find('>', at);
        if (close == std::string::npos) {
            fail("unterminated tag");
            return false;
        }
        const bool self_closed = xml[close - 1] == '/';
        at = close + 1;
        if (self_closed) name += "/";
        return true;
    }

    bool expectClose(const std::string& name) {
        skipProlog();
        if (xml.compare(at, name.size() + 3, "</" + name + ">") != 0) {
            return fail("expected </" + name + ">");
        }
        at += name.size() + 3;
        return true;
    }

    std::string textUntilTag() {
        const auto end = xml.find('<', at);
        std::string raw = xml.substr(at, end == std::string::npos ? std::string::npos : end - at);
        at = end == std::string::npos ? xml.size() : end;
        std::string out;
        out.reserve(raw.size());
        for (std::size_t i = 0; i < raw.size(); ++i) {
            if (raw[i] == '&') {
                const auto semi = raw.find(';', i);
                const std::string entity = semi == std::string::npos
                                               ? std::string()
                                               : raw.substr(i + 1, semi - i - 1);
                if (entity == "amp") out += '&';
                else if (entity == "lt") out += '<';
                else if (entity == "gt") out += '>';
                else if (entity == "quot") out += '"';
                else if (entity == "apos") out += '\'';
                else out += '&';
                i = semi == std::string::npos ? raw.size() : semi;
                continue;
            }
            out += raw[i];
        }
        return out;
    }

    static std::string hexOf(const std::string& bytes) {
        static const char* digits = "0123456789abcdef";
        std::string out;
        out.reserve(bytes.size() * 2);
        for (const unsigned char c : bytes) {
            out += digits[c >> 4];
            out += digits[c & 0xf];
        }
        return out;
    }

    // Base64 payload for <data> (no whitespace-free requirement, '*' padding of
    // GNUstep is not accepted: fail loudly instead of guessing).
    static bool decodeBase64(const std::string& input, std::string& out) {
        static const std::string alphabet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string clean;
        for (const char c : input) {
            if (std::isspace(static_cast<unsigned char>(c))) continue;
            clean += c;
        }
        if (clean.size() % 4 != 0) return false;
        out.clear();
        int buffer = 0, bits = 0;
        for (const char c : clean) {
            if (c == '=') continue;   // padding only truncates the last group
            const auto index = alphabet.find(c);
            if (index == std::string::npos) return false;
            buffer = (buffer << 6) | static_cast<int>(index);
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out += static_cast<char>((buffer >> bits) & 0xff);
            }
        }
        return true;
    }

    bool parseValue(SaveValue& out, const std::string& tag);
    bool parseDict(SaveValue& out);
    bool parseArray(SaveValue& out);
};

bool Parser::parseDict(SaveValue& out) {
    out = SaveValue{};
    out.kind = SaveValue::Kind::Dict;
    for (;;) {
        std::string tag;
        if (!openTag(tag)) return false;
        if (tag == "/dict") return true;
        if (tag != "key") return fail("expected <key> inside <dict>, got <" + tag + ">");
        const std::string key = textUntilTag();
        if (!expectClose("key")) return false;
        SaveValue value;
        if (!openTag(tag)) return false;
        if (!parseValue(value, tag)) return false;
        out.dict[key] = std::move(value);
    }
}

bool Parser::parseArray(SaveValue& out) {
    out = SaveValue{};
    out.kind = SaveValue::Kind::Array;
    for (;;) {
        std::string tag;
        if (!openTag(tag)) return false;
        if (tag == "/array") return true;
        SaveValue value;
        if (!parseValue(value, tag)) return false;
        out.array.push_back(std::move(value));
    }
}

bool Parser::parseValue(SaveValue& out, const std::string& tag) {
    if (tag == "dict") return parseDict(out);
    if (tag == "array") return parseArray(out);
    if (tag == "string") {
        out = SaveValue{};
        out.kind = SaveValue::Kind::String;
        out.text = textUntilTag();
        return expectClose("string");
    }
    if (tag == "integer" || tag == "real") {
        const std::string raw = textUntilTag();
        if (!expectClose(tag)) return false;
        out = SaveValue{};
        errno = 0;
        char* end = nullptr;
        if (tag == "integer") {
            out.kind = SaveValue::Kind::Integer;
            out.integer = std::strtoll(raw.c_str(), &end, 10);
        } else {
            out.kind = SaveValue::Kind::Real;
            out.real = std::strtod(raw.c_str(), &end);
        }
        if (errno != 0 || end == raw.c_str() || (end && *end != '\0')) {
            return fail("malformed <" + tag + "> value");
        }
        return true;
    }
    if (tag == "true/" || tag == "false/") {
        out = SaveValue{};
        out.kind = SaveValue::Kind::Bool;
        out.boolean = tag == "true/";
        return true;
    }
    if (tag == "data") {
        const std::string raw = textUntilTag();
        if (!expectClose("data")) return false;
        std::string bytes;
        if (!decodeBase64(raw, bytes)) return fail("malformed <data> base64");
        out = SaveValue{};
        out.kind = SaveValue::Kind::Data;
        out.text = hexOf(bytes);
        return true;
    }
    if (tag == "date") {
        // Documented stub simplification: the timestamp is preserved as text;
        // no calendar semantics are modelled.
        out = SaveValue{};
        out.kind = SaveValue::Kind::String;
        out.text = textUntilTag();
        return expectClose("date");
    }
    return fail("unsupported plist value tag <" + tag + ">");
}

}  // namespace

bool parseXmlPlist(const std::string& xml, SaveValue& out, std::string* error) {
    Parser parser{xml, 0, error};
    std::string tag;
    if (!parser.openTag(tag)) return false;
    if (tag != "plist") {
        if (error) *error = "root element is <" + tag + ">, expected <plist>";
        return false;
    }
    if (!parser.openTag(tag)) return false;
    if (!parser.parseValue(out, tag)) return false;
    return parser.expectClose("plist");
}

const SaveValue* SaveDict::objectForKey(const std::string& key) const {
    if (!value_.isDict()) return nullptr;
    const auto it = value_.dict.find(key);
    return it == value_.dict.end() ? nullptr : &it->second;
}

long long SaveDict::intValue(const SaveValue* value) {
    if (!value || value->isNil()) return 0;
    switch (value->kind) {
        case SaveValue::Kind::Integer: return value->integer;
        case SaveValue::Kind::Real: return static_cast<long long>(value->real);
        case SaveValue::Kind::Bool: return value->boolean ? 1 : 0;
        case SaveValue::Kind::String: {
            char* end = nullptr;
            const long long parsed = std::strtoll(value->text.c_str(), &end, 10);
            return end == value->text.c_str() ? 0 : parsed;
        }
        default: return 0;
    }
}

double SaveDict::doubleValue(const SaveValue* value) {
    if (!value || value->isNil()) return 0.0;
    switch (value->kind) {
        case SaveValue::Kind::Integer: return static_cast<double>(value->integer);
        case SaveValue::Kind::Real: return value->real;
        case SaveValue::Kind::Bool: return value->boolean ? 1.0 : 0.0;
        case SaveValue::Kind::String: {
            char* end = nullptr;
            const double parsed = std::strtod(value->text.c_str(), &end);
            return end == value->text.c_str() ? 0.0 : parsed;
        }
        default: return 0.0;
    }
}

float SaveDict::floatValue(const SaveValue* value) {
    return static_cast<float>(doubleValue(value));
}

unsigned long long SaveDict::unsignedLongValue(const SaveValue* value) {
    const long long signed_value = intValue(value);
    return signed_value < 0 ? 0ULL : static_cast<unsigned long long>(signed_value);
}

bool SaveDict::boolValue(const SaveValue* value) {
    if (!value || value->isNil()) return false;
    switch (value->kind) {
        case SaveValue::Kind::Integer: return value->integer != 0;
        case SaveValue::Kind::Real: return value->real != 0.0;
        case SaveValue::Kind::Bool: return value->boolean;
        case SaveValue::Kind::String:
            return value->text == "true" || value->text == "YES" ||
                   value->text == "1";
        default: return false;
    }
}

std::size_t SaveDict::count(const SaveValue* value) {
    if (!value || value->isNil()) return 0;
    if (value->isArray()) return value->array.size();
    if (value->isDict()) return value->dict.size();
    return 0;
}

const SaveValue* SaveDict::objectAtIndex(const SaveValue* value,
                                         std::size_t index) const {
    if (!value || !value->isArray() || index >= value->array.size()) return nullptr;
    return &value->array[index];
}

}  // namespace bh176
