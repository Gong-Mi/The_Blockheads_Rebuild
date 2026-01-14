#include "settings_manager.h"
#include <fstream>
#include <sstream>

void SettingsManager::setBool(const std::string& key, bool value) {
    cache[key] = value ? "1" : "0";
    save();
}

bool SettingsManager::getBool(const std::string& key, bool defaultValue) {
    if (cache.count(key)) {
        return cache[key] == "1";
    }
    return defaultValue;
}

void SettingsManager::setFloat(const std::string& key, float value) {
    cache[key] = std::to_string(value);
    save();
}

float SettingsManager::getFloat(const std::string& key, float defaultValue) {
    if (cache.count(key)) {
        return std::stof(cache[key]);
    }
    return defaultValue;
}

void SettingsManager::load(const std::string& path) {
    storagePath = path;
    std::ifstream file(path);
    if (!file.is_open()) return;

    std::string line;
    while (std::getline(file, line)) {
        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            cache[key] = value;
        }
    }
}

void SettingsManager::save() {
    if (storagePath.empty()) return;
    std::ofstream file(storagePath);
    for (const auto& pair : cache) {
        file << pair.first << "=" << pair.second << "\n";
    }
}
