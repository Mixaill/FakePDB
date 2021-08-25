#pragma once

//stdlib
#include <cstdint>
#include <vector>
#include <string>

namespace FakePDB {
    class CommandInterface {
    public:
        virtual ~CommandInterface() = default;

        virtual int32_t GetArgsMin() = 0;
        virtual int32_t GetArgsMax() = 0;

        virtual std::string GetCommandName() = 0;
        virtual std::vector<std::string> GetCommandUsage() = 0;
        virtual std::string GetCommandDescription() = 0;


        virtual int Run(int argc, char* argv[]) = 0;
    };
}