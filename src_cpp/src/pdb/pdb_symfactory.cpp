/**
   Copyright 2019 LLVM project
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

//llvm
#include <llvm/DebugInfo/CodeView/ContinuationRecordBuilder.h>

//fakepdb
#include "pdb/pdb_symfactory.h"

namespace FakePDB::PDB {

    PdbSymFactory::PdbSymFactory(PE::PeFile &peFile) : _pefile(peFile) {

    }

    llvm::pdb::BulkPublic PdbSymFactory::createPublicSymbol(Data::Function &idaFunc) const {
        llvm::pdb::BulkPublic public_sym;
        public_sym.Name = idaFunc.name.c_str();
        public_sym.NameLen = idaFunc.name.size();
        public_sym.Segment = _pefile.GetSectionIndexForRVA(idaFunc.start_rva);
        public_sym.Offset = _pefile.GetSectionOffsetForRVA(idaFunc.start_rva);

        public_sym.setFlags(llvm::codeview::PublicSymFlags::Code | llvm::codeview::PublicSymFlags::Function);

        return public_sym;
    }

    llvm::pdb::BulkPublic
    PdbSymFactory::createPublicSymbol(const Data::Label &idaLabel, const Data::Function &idaFunc) const {
        llvm::pdb::BulkPublic public_sym;

        public_sym.Name = idaLabel.name.c_str();
        public_sym.NameLen = idaLabel.name.size();
        public_sym.Segment = _pefile.GetSectionIndexForRVA(idaLabel.offset + idaFunc.start_rva);
        public_sym.Offset = _pefile.GetSectionOffsetForRVA(idaLabel.offset + idaFunc.start_rva);

        public_sym.setFlags(llvm::codeview::PublicSymFlags::Code);

        return public_sym;
    }

    llvm::pdb::BulkPublic PdbSymFactory::createPublicSymbol(Data::Name &idaName) const {
        llvm::pdb::BulkPublic public_sym;

        public_sym.Name = idaName.name.c_str();
        public_sym.NameLen = idaName.name.size();
        public_sym.Segment = _pefile.GetSectionIndexForRVA(idaName.rva);
        public_sym.Offset = _pefile.GetSectionOffsetForRVA(idaName.rva);

        public_sym.setFlags(llvm::codeview::PublicSymFlags::None);

        return public_sym;
    }
}
