//stdlib
#include <filesystem>
#include <fstream>
#include <iostream>

//nlohmann
#include "nlohmann/json.hpp"

//FakePDB
#include "commands/command_interface.h"
#include "data/db.h"
#include "types/hex.h"
#include "pdb/pdb_creator.h"


namespace FakePDB::Commands {
    class CommandPdbGenerate : public CommandInterface {
    public:
        ~CommandPdbGenerate() = default;

        int32_t GetArgsMin() override {
            return 2;
        };

        int32_t GetArgsMax() override {
            return 3;
        };

        std::string GetCommandName() override {
            return "pdb_generate";
        }

        std::vector<std::string> GetCommandUsage() override {
            return {"[-l] <json filepath> <output file>" };
        }

        std::string GetCommandDescription() override {
            return "generate PDB file for given file";
        }

        int Run(int argc, char* argv[]) override {
            bool with_labels = false;
            size_t arg_json = 2;
            if (argc > 5 && std::string(argv[2]) == "-l") {
                arg_json++;
                with_labels = true;
            }
            std::filesystem::path path_json = argv[arg_json];
            std::filesystem::path path_out  = argv[arg_json+1];

            if (!std::filesystem::exists(path_json)) {
                std::cerr << ".json file does not exists";
                return 3;
            }

            Data::DB ida_db(path_json);
            PDB::PdbCreator creator;
            creator.Initialize(ida_db, with_labels);

            std::filesystem::create_directories(path_out.parent_path());

            creator.Commit(path_out);

            return 0;
        }
    };
}