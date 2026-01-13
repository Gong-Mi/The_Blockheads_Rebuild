#include "command_processor.h"

void CommandProcessor::init() {
    commandMap["/BAN"] = {"/BAN", ADMIN, "Ban player and device"};
    commandMap["/KICK"] = {"/KICK", MOD, "Kick player temporarily"};
    commandMap["/PVP-ON"] = {"/PVP-ON", ADMIN, "Enable PvP"};
    commandMap["/REPAIR"] = {"/REPAIR", ADMIN, "Repair glitched tiles"};
    commandMap["/SET-PASSWORD"] = {"/SET-PASSWORD", OWNER, "Set world password"};
}

bool CommandProcessor::execute(const std::string& cmd, Permission userPerm) {
    if (commandMap.count(cmd)) {
        if (userPerm >= commandMap[cmd].requiredPermission) {
            return true;
        }
    }
    return false;
}