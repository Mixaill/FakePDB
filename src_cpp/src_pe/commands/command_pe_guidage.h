//stdlib
#include <filesystem>

//FakePDB
#include "commands/command_interface.h"
#include "pe/pe_file.h"
#include "types/guid.h"
#include "types/hex.h"


namespace FakePDB::Commands {
    class CommandPeGuidAge : public CommandInterface {
public:
    ~CommandPeGuidAge() = default;

    int32_t GetArgsMin() override {
        return 1;
    };

    int32_t GetArgsMax() override {
        return 1;
    };

    std::string GetCommandName() override {
        return "pe_guidage";
    }

    std::vector<std::string> GetCommandUsage() override {
        return { "<pe_filepath>" };
    }

    std::string GetCommandDescription() override {
        return "returns PDB folder name for symbol server";
    }

    int Run(int argc, char* argv[]) override {
        std::string pathExe = argv[2];

        if (!std::filesystem::exists(pathExe)) {
            std::cerr << "file does not exists";
            return 1;
        }

        PE::PeFile pefile(pathExe);
        std::cout << (Common::GUID::ToHex(pefile.GetPdbGuid()) + Common::Hex::IntToHex(pefile.GetPdbAge()));
        return 0;
    }
};

}
