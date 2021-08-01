//llvm
#include <llvm/Object/COFFImportFile.h>

//fakepdb
#include "coff/lib_creator.h"

namespace FakePDB::COFF {
    bool LibCreator::Create(Data::DB &db, std::filesystem::path& path) {
        std::vector<llvm::object::COFFShortExport> exports;
        for(auto& ex : db.Exports()){
            llvm::object::COFFShortExport entry{};
            entry.Ordinal = ex.ordinal;
            entry.Name = ex.name;
            if(ex.type == "data"){
                entry.Data = true;
            }
            exports.push_back(entry);
        }

        auto info = db.General();

        auto machine_type =  info.getMachineType();
        if(machine_type == llvm::COFF::IMAGE_FILE_MACHINE_UNKNOWN){
            return false;
        }

        auto err = llvm::object::writeImportLibrary(db.General().filename,path.string(), exports,machine_type,false);
        if(err){
            return false;
        }

        return true;
    }
}

