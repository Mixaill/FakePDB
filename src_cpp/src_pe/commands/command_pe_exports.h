//stdlib
#include <filesystem>
#include <fstream>
#include <iostream>

//nlohmann
#include "nlohmann/json.hpp"

//FakePDB
#include "commands/command_interface.h"
#include "data/db.h"
#include "pe/pe_file.h"
#include "types/hex.h"


namespace FakePDB::Commands {
    class CommandPeExports : public CommandInterface {
    public:
        ~CommandPeExports() = default;

        int32_t GetArgsMin() override {
            return 1;
        };

        int32_t GetArgsMax() override {
            return 2;
        };

        std::string GetCommandName() override {
            return "pe_exports";
        }

        std::vector<std::string> GetCommandUsage() override {
            return { "<pe_filepath>", "<pe_filepath> [json_path]" };
        }

        std::string GetCommandDescription() override {
            return "returns exports in the given PE file";
        }

        int Run(int argc, char* argv[]) override {
            std::string pathExe = argv[2];

            if (!std::filesystem::exists(pathExe)) {
                std::cerr << "file does not exists";
                return 1;
            }

            PE::PeFile pefile(pathExe);

            Data::DB db;
            db.General().filename = std::filesystem::path(pathExe).filename().string();
            db.General().architecture = pefile.GetMachineName();
            db.General().bitness = pefile.GetMachineBitness();
            db.Exports() = pefile.GetExports();
            db.Segments() = pefile.GetSections();

            if (argc == 3)
            {
                for (auto& exp : db.Exports()) {
                    std::cout << "Name   : " << exp.name << std::endl;
                    std::cout << "Ordinal: " << exp.ordinal << std::endl;
                    std::cout << "RVA    : 0x" << Common::Hex::IntToHex(exp.rva) << std::endl;
                    std::cout << std::endl;
                }
            }

            if (argc == 4) {
                auto json_path = std::filesystem::path(argv[3]);
                db.Save(json_path);
            }

            return 0;
        }
    };
}