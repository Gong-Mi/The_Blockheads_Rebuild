#ifndef COMMAND_PROCESSOR_H
#define COMMAND_PROCESSOR_H

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

    void init();
    bool execute(const std::string& cmd, Permission userPerm);
};

#endif
