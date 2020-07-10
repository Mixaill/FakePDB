/**
   Copyright 2019 Mikhail Paulyshka

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

#include <llvm/DebugInfo/CodeView/SymbolRecord.h>

#include <llvm/DebugInfo/MSF/MSFBuilder.h>

#include <llvm/DebugInfo/PDB/Native/PDBFileBuilder.h>
#include <llvm/DebugInfo/PDB/Native/DbiStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/GSIStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/InfoStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/TpiStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/RawConstants.h>

#include "pefile.h"
#include "idadb.h"

class PdbCreator {
public:

    PdbCreator(PeFile& peFile);

    bool Initialize();

    void AddNatvisFile(std::filesystem::path& path);

    void ImportIDA(IdaDb& ida_db);

    bool Commit(std::filesystem::path& path);

private:
    void addTypeInfo(llvm::pdb::TpiStreamBuilder& TpiBuilder);

    void processGSI(IdaDb& ida_db);

    bool processSections();

    void processSymbols();

    llvm::pdb::BulkPublic createPublicSymbol(IdaFunction& idaFunc);
    llvm::pdb::BulkPublic createPublicSymbol(const IdaLabel& idaLabel, const IdaFunction& idaFunc);
    llvm::pdb::BulkPublic createPublicSymbol(IdaName& idaName);

    PeFile& _pefile;

    llvm::BumpPtrAllocator _allocator;
    llvm::pdb::PDBFileBuilder _pdbBuilder;
    std::vector<llvm::pdb::SecMapEntry> _sectionMap;
};
