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
#include "pdb_symfactory.h"

namespace FakePDB::PDB {

    llvm::pdb::BulkPublic PdbSymFactory::createPublicSymbol(const Data::SegmentArray& segments, const Data::Function &idaFunc) {
        llvm::pdb::BulkPublic public_sym;
        public_sym.Name = idaFunc.name.c_str();
        public_sym.NameLen = idaFunc.name.size();
        public_sym.Segment = segments.getSectionIndexByRva(idaFunc.start_rva);
        public_sym.Offset = segments.getSectionOffsetByRva(idaFunc.start_rva);

        public_sym.setFlags(llvm::codeview::PublicSymFlags::Code | llvm::codeview::PublicSymFlags::Function);

        return public_sym;
    }

    llvm::pdb::BulkPublic
    PdbSymFactory::createPublicSymbol(const Data::SegmentArray& segments, const Data::Label &idaLabel, const Data::Function &idaFunc) {
        llvm::pdb::BulkPublic public_sym;

        public_sym.Name = idaLabel.name.c_str();
        public_sym.NameLen = idaLabel.name.size();
        public_sym.Segment = segments.getSectionIndexByRva(idaLabel.offset + idaFunc.start_rva);
        public_sym.Offset = segments.getSectionOffsetByRva(idaLabel.offset + idaFunc.start_rva);

        public_sym.setFlags(llvm::codeview::PublicSymFlags::Code);

        return public_sym;
    }

    llvm::pdb::BulkPublic PdbSymFactory::createPublicSymbol(const Data::SegmentArray& segments, const Data::Name &idaName) {
        llvm::pdb::BulkPublic public_sym;

        public_sym.Name = idaName.name.c_str();
        public_sym.NameLen = idaName.name.size();
        public_sym.Segment = segments.getSectionIndexByRva(idaName.rva);
        public_sym.Offset = segments.getSectionOffsetByRva(idaName.rva);

        public_sym.setFlags(llvm::codeview::PublicSymFlags::None);

        return public_sym;
    }
}
