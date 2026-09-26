#ifndef ORIGINAL_SAVE_DICT_H
#define ORIGINAL_SAVE_DICT_H

// Stub layer for the client-side assembly app: a minimal GNUstep/Foundation
// stand-in for the surface the recovered loaders actually use.
//
// Modelled selector semantics (equal to the recovered contracts, not to the
// full Foundation):
//   objectForKey:        missing key -> nil (never a default object)
//   intValue             nil -> 0, integer -> value, real -> truncation,
//                        string -> leading integer (0 when none)
//   floatValue/doubleValue  nil -> 0.0f / 0.0
//   unsignedLongValue    nil -> 0
//   boolValue            nil -> false, number -> != 0, string -> "true"/"YES"/"1"
//   count                nil -> 0, array/dict -> element count
//   objectAtIndex:       out of range -> nil
//
// Anything the recovered work needs that is NOT modelled must be recorded
// through noteStub() instead of returning an invented value: the app report
// carries the counters so a gap is visible rather than guessed.
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace bh176 {

struct SaveValue {
    enum class Kind { Nil, Dict, Array, String, Integer, Real, Bool, Data };
    Kind kind = Kind::Nil;
    std::map<std::string, SaveValue> dict;
    std::vector<SaveValue> array;
    std::string text;      // String / Data (hex) / Date (raw text, stub)
    long long integer = 0;
    double real = 0.0;
    bool boolean = false;

    bool isNil() const { return kind == Kind::Nil; }
    bool isDict() const { return kind == Kind::Dict; }
    bool isArray() const { return kind == Kind::Array; }
};

// Minimal XML plist (format v1.0) reader: dict/key/string/integer/real/
// true/false/data/array. Unknown *value* tags are an error (the caller counts
// the record as malformed); `date` is kept as its raw text by documented stub
// simplification. Returns false and fills `error` on malformed input.
bool parseXmlPlist(const std::string& xml, SaveValue& out, std::string* error);

class SaveDict {
public:
    SaveDict() = default;
    explicit SaveDict(SaveValue value) : value_(std::move(value)) {}

    const SaveValue& value() const { return value_; }

    // objectForKey: (string keys only; a non-dict receiver yields nil)
    const SaveValue* objectForKey(const std::string& key) const;

    static long long intValue(const SaveValue* value);
    static float floatValue(const SaveValue* value);
    static double doubleValue(const SaveValue* value);
    static unsigned long long unsignedLongValue(const SaveValue* value);
    static bool boolValue(const SaveValue* value);
    static std::size_t count(const SaveValue* value);
    const SaveValue* objectAtIndex(const SaveValue* value, std::size_t index) const;

    void noteStub(const char* selector) const {
        ++stub_hits_;
        last_stub_ = selector;
    }
    std::size_t stubHits() const { return stub_hits_; }
    const std::string& lastStub() const { return last_stub_; }

private:
    SaveValue value_;
    mutable std::size_t stub_hits_ = 0;
    mutable std::string last_stub_;
};

}  // namespace bh176

#endif  // ORIGINAL_SAVE_DICT_H
