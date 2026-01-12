#include <string>
#include <vector>
#include <map>

class CommandProcessor {
public:
    enum Permission { OWNER, ADMIN, MOD, PLAYER };

    struct Command {
        std::string name;
        Permission requiredPermission;
        std::string description;
    };

    std::map<std::string, Command> commandMap;

    void init() {
        // --- 还原自二进制字符串挖掘结果 ---
        commandMap["/BAN"] = {"/BAN", ADMIN, "Ban player and device"};
        commandMap["/KICK"] = {"/KICK", MOD, "Kick player temporarily"};
        commandMap["/PVP-ON"] = {"/PVP-ON", ADMIN, "Enable PvP"};
        commandMap["/REPAIR"] = {"/REPAIR", ADMIN, "Repair glitched tiles"};
        commandMap["/SET-PASSWORD"] = {"/SET-PASSWORD", OWNER, "Set world password"};
        // ... 继续添加挖掘出的所有命令
    }

    bool execute(const std::string& cmd, Permission userPerm) {
        if (commandMap.count(cmd)) {
            if (userPerm >= commandMap[cmd].requiredPermission) {
                // 执行逻辑
                return true;
            }
        }
        return false;
    }
};
