//FakePDB
#include "commands/command_interface.h"
#include "pe/pe_file.h"
#include "types/hex.h"


namespace FakePDB::Commands {
    class CommandPeTimestamp : public CommandInterface {
    public:
        ~CommandPeTimestamp() = default;

        int32_t GetArgsMin() override {
            return 1;
        };

        int32_t GetArgsMax() override {
            return 1;
        };

        std::string GetCommandName() override {
            return "pe_timestamp";
        }

        std::vector<std::string> GetCommandUsage() override {
            return { "<pe_filepath>" };
        }

        std::string GetCommandDescription() override {
            return "returns EXE/DLL folder name for symbol server";
        }

        int Run(int argc, char* argv[]) override {
            std::string pathExe = argv[2];

            if (!std::filesystem::exists(pathExe)) {
                std::cerr << ".exe file does not exists";
                return 1;
            }

            PE::PeFile pefile(pathExe);

            std::cout << (Common::Hex::IntToHex(pefile.GetTimestamp()) + Common::Hex::IntToHex(pefile.GetImageSize()));
            return 0;
        }
    };
}
