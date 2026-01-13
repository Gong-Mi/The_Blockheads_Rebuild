#ifndef SETTINGS_MANAGER_H
#define SETTINGS_MANAGER_H

#include <string>
#include <map>

class SettingsManager {
public:
    static SettingsManager& getInstance() {
        static SettingsManager instance;
        return instance;
    }

    // --- Original Settings Keys ---
    static constexpr const char* KEY_MUSIC_ENABLED = "music_enabled";
    static constexpr const char* KEY_SOUND_ENABLED = "sound_enabled";
    static constexpr const char* KEY_HD_TEXTURES = "hd_textures";
    static constexpr const char* KEY_LEFT_HANDED = "left_handed";

    void setBool(const std::string& key, bool value);
    bool getBool(const std::string& key, bool defaultValue = true);

    void setFloat(const std::string& key, float value);
    float getFloat(const std::string& key, float defaultValue = 1.0f);

private:
    SettingsManager() {}
    std::map<std::string, std::string> cache; 
};

#endif
