/**
   Copyright 2019-2021 Mikhail Paulyshka

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**/

#pragma once

//llvm
#include <llvm/DebugInfo/PDB/Native/PDBFileBuilder.h>
#include <llvm/DebugInfo/PDB/Native/TpiStreamBuilder.h>

//fakepdb
#include "data/db.h"
#include "pdb/pdb_symfactory.h"
#include "pe/pe_file.h"

namespace FakePDB::PDB {
    class PdbCreator {
    public:

        PdbCreator(PE::PeFile &peFile, bool withLabels);

        bool Initialize();

        void AddNatvisFile(std::filesystem::path &path);

        void ImportIDA(Data::DB &ida_db);

        bool Commit(std::filesystem::path &path);

    private:
        void addTypeInfo(llvm::pdb::TpiStreamBuilder &TpiBuilder);

        void processGSI(Data::DB &ida_db);

        bool processSections();

        void processSymbols();


        PE::PeFile &_pefile;
        PDB::PdbSymFactory _symfactory;

        bool _withLabels;

        llvm::BumpPtrAllocator _allocator;
        llvm::pdb::PDBFileBuilder _pdbBuilder;
        std::vector<llvm::pdb::SecMapEntry> _sectionMap;
    };
}
