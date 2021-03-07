//stdlib
#include <filesystem>
#include <fstream>
#include <iostream>

//nlohmann
#include "nlohmann/json.hpp"

//FakePDB
#include "commands/command_interface.h"
#include "coff/lib_creator.h"

namespace FakePDB::Commands {
    class CommandCoffCreatelib : public CommandInterface {
    public:
        ~CommandCoffCreatelib() = default;

        int32_t GetArgsMin() override {
            return 2;
        };

        int32_t GetArgsMax() override {
            return 2;
        };

        std::string GetCommandName() override {
            return "coff_createlib";
        }

        std::vector<std::string> GetCommandUsage() override {
            return { "<json_filepath> [lib_path]" };
        }

        std::string GetCommandDescription() override {
            return "creates .lib file from .json";
        }

        int Run(int argc, char* argv[]) override {
            std::filesystem::path path_json = argv[2];
            std::filesystem::path path_lib = argv[3];

            if (!std::filesystem::exists(path_json)) {
                std::cerr << "json file does not exists";
                return 1;
            }

            Data::DB db(path_json);

            COFF::LibCreator libCreator;
            if(!libCreator.Create(db, path_lib)) {
                std::cerr << "failed to create lib";
                return 2;
            }

            return 0;
        }
    };
}