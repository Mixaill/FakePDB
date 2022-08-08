//llvm
#include <llvm/Object/COFFImportFile.h>

//fakepdb
#include "lib_creator.h"

namespace FakePDB::COFF {
    bool LibCreator::Create(Data::DB& db, std::filesystem::path& path) {
        auto info = db.General();
        auto machine_type = info.getMachineType();
        if (machine_type == llvm::COFF::IMAGE_FILE_MACHINE_UNKNOWN) {
            return false;
        }

        std::vector<llvm::object::COFFShortExport> exports;
        for (const auto& ex : db.Exports()) {
            llvm::object::COFFShortExport entry{};
            entry.Ordinal = ex.ordinal;

            // https://docs.microsoft.com/en-us/cpp/build/reference/decorated-names
            entry.Name = ex.name;
            if (machine_type == llvm::COFF::IMAGE_FILE_MACHINE_I386 && ex.calling_convention != "fastcall" && ex.calling_convention != "vectorcall") {
                entry.Name = "_" + entry.Name;
            }

            if (ex.type == "data") {
                entry.Data = true;
            }

            exports.push_back(entry);
        }

        auto err = llvm::object::writeImportLibrary(db.General().filename, path.string(), exports, machine_type, false);
        if (err) {
            return false;
        }

        return true;
    }
}

