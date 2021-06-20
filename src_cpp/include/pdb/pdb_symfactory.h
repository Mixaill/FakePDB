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
#include <llvm/DebugInfo/CodeView/TypeRecord.h>
#include <llvm/DebugInfo/PDB/Native/GSIStreamBuilder.h>

//fakepdb
#include "data/db.h"
#include "pe/pe_file.h"

namespace FakePDB::PDB {

    class PdbSymFactory{
    public:
        explicit PdbSymFactory(PE::PeFile& peFile);

        [[nodiscard]] llvm::pdb::BulkPublic createPublicSymbol(Data::Function &idaFunc) const;
        [[nodiscard]] llvm::pdb::BulkPublic createPublicSymbol(const Data::Label &idaLabel, const Data::Function &idaFunc) const;
        [[nodiscard]] llvm::pdb::BulkPublic createPublicSymbol(Data::Name &idaName) const;
    private:

        PE::PeFile& _pefile;
    };
}