//stdlib
#include <filesystem>
#include <fstream>
#include <iostream>

//nlohmann
#include "nlohmann/json.hpp"

//FakePDB
#include "commands/command_interface.h"
#include "common/hex.h"
#include "pe/pe_file.h"
#include "data/db.h"
#include "pdb/pdb_creator.h"

namespace FakePDB::Commands {
    class CommandPdbGenerate : public CommandInterface {
    public:
        ~CommandPdbGenerate() = default;

        int32_t GetArgsMin() override {
            return 3;
        };

        int32_t GetArgsMax() override {
            return 4;
        };

        std::string GetCommandName() override {
            return "pdb_generate";
        }

        std::vector<std::string> GetCommandUsage() override {
            return {"[-l] <exe filepath> <json filepath> <output file>" };
        }

        std::string GetCommandDescription() override {
            return "generate PDB file for given file";
        }

        int Run(int argc, char* argv[]) override {
            bool with_labels = false;
            size_t arg_exe = 2;
            if (argc > 5 && std::string(argv[2]) == "-l") {
                arg_exe++;
                with_labels = true;
            }
            std::filesystem::path path_exe  = argv[arg_exe];
            std::filesystem::path path_json = argv[arg_exe+1];
            std::filesystem::path path_out  = argv[arg_exe+2];

            if (!std::filesystem::exists(path_exe)) {
                std::cerr << ".exe file does not exists";
                return 2;
            }

            if (!std::filesystem::exists(path_json)) {
                std::cerr << ".json file does not exists";
                return 3;
            }

            PE::PeFile pefile(path_exe);
            Data::DB ida_db(path_json);
            PDB::PdbCreator creator(pefile, with_labels);

            creator.Initialize();
            creator.ImportIDA(ida_db);

            std::filesystem::create_directories(path_out.parent_path());
            creator.Commit(path_out);

            return 0;
        }
    };
}