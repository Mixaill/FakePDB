#pragma once

#include <iostream>
#include <memory>
#include <vector>

#include "commands/command_interface.h"

namespace FakePDB {

    class CommandExecutor {
    public:
        void AddCommand(std::shared_ptr<CommandInterface> i);

        int Run(int argc, char* argv[]);

        void Usage();

    private:
        std::vector<std::shared_ptr<CommandInterface>> _commands;
    };
}