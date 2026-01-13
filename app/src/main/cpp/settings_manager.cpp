#include "settings_manager.h"
#include <fstream>

void SettingsManager::setBool(const std::string& key, bool value) {
    cache[key] = value ? "1" : "0";
}

bool SettingsManager::getBool(const std::string& key, bool defaultValue) {
    if (cache.count(key)) {
        return cache[key] == "1";
    }
    return defaultValue;
}

void SettingsManager::setFloat(const std::string& key, float value) {
    cache[key] = std::to_string(value);
}

float SettingsManager::getFloat(const std::string& key, float defaultValue) {
    if (cache.count(key)) {
        return std::stof(cache[key]);
    }
    return defaultValue;
}
