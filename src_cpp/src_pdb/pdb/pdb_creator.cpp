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
#include <llvm/DebugInfo/CodeView/SymbolSerializer.h>
#include <llvm/DebugInfo/MSF/MSFBuilder.h>
#include <llvm/DebugInfo/PDB/Native/DbiModuleDescriptorBuilder.h>
#include <llvm/DebugInfo/PDB/Native/DbiStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/InfoStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/RawTypes.h>
#include <llvm/Object/COFF.h>
#include <llvm/Support/Allocator.h>
#include <llvm/Support/ErrorOr.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/Parallel.h>

//fakepdb
#include "pdb_creator.h"
#include "pdb_symfactory.h"
#include "pe/pe_file.h"


namespace FakePDB::PDB {

    template<typename R, class FuncTy>
    void parallelSort(R &&Range, FuncTy Fn) {
        llvm::parallelSort(std::begin(Range), std::end(Range), Fn);
    }

    PdbCreator::PdbCreator() : _pdbBuilder(_allocator)
    {
    }

    bool PdbCreator::Initialize(Data::DB &ida_db, std::filesystem::path& path_exe, bool withLabels) {
        _withLabels = withLabels;

        //initialize builder
        if (_pdbBuilder.initialize(4096)) {
            return false;
        }

        // Create streams in MSF for predefined streams, namely PDB, TPI, DBI and IPI.
        for (int I = 0; I < (int) llvm::pdb::kSpecialStreamCount; ++I) {
            if (_pdbBuilder.getMsfBuilder().addStream(0).takeError()) {
                return false;
            }
        }

        // Add an Info stream.
        auto& InfoBuilder = _pdbBuilder.getInfoBuilder();
        InfoBuilder.setVersion(llvm::pdb::PdbRaw_ImplVer::PdbImplVC70);
        InfoBuilder.setHashPDBContentsToGUID(false);

        // set GUID and Aage
        if (std::filesystem::exists(path_exe)) {
            PE::PeFile pe_file(path_exe);
            InfoBuilder.setGuid(pe_file.GetPdbGuid());
            InfoBuilder.setAge(pe_file.GetPdbAge());
        }
        else {
            llvm::codeview::GUID guid{};
            auto guid_d = ida_db.PE().pdb_guid;
            memcpy(guid.Guid, guid_d.data(), guid_d.size());

            InfoBuilder.setGuid(guid);
            InfoBuilder.setAge(ida_db.PE().pdb_age);
        }

        //Add an empty DBI stream.
        auto& DbiBuilder = _pdbBuilder.getDbiBuilder();
        DbiBuilder.setVersionHeader(llvm::pdb::PdbDbiV70);
        DbiBuilder.setMachineType(static_cast<llvm::pdb::PDB_Machine>(ida_db.PE().image_machine));
        DbiBuilder.setFlags(llvm::pdb::DbiFlags::FlagHasCTypesMask);
        DbiBuilder.setAge(InfoBuilder.getAge());

        // Technically we are not link.exe 14.11, but there are known cases where
        // debugging tools on Windows expect Microsoft-specific version numbers or
        // they fail to work at all.  Since we know we produce PDBs that are
        // compatible with LINK 14.11, we set that version number here.
        DbiBuilder.setBuildNumber(14, 11);

        importIDA(ida_db);

        return true;
    }

    void PdbCreator::AddNatvisFile(std::filesystem::path &path) {
        llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> DataOrErr = llvm::MemoryBuffer::getFile(path.string());
        _pdbBuilder.addInjectedSource(path.string(), std::move(*DataOrErr));
    }

    void PdbCreator::importIDA(Data::DB &ida_db) {
        //TPI
        addTypeInfo(_pdbBuilder.getTpiBuilder());

        //IPI
        addTypeInfo(_pdbBuilder.getIpiBuilder());

        //GSI
        processGSI(ida_db);

        //Symbols
        processSymbols();

        //Sections
        processSections(ida_db);
    }

    bool PdbCreator::Commit(std::filesystem::path &path) {
        std::filesystem::create_directories(path.parent_path());
        auto guid = _pdbBuilder.getInfoBuilder().getGuid();
        if (_pdbBuilder.commit(path.string(), &guid)) {
            return false;
        }

        return true;
    }

    void PdbCreator::addTypeInfo(llvm::pdb::TpiStreamBuilder &TpiBuilder) {
        // Start the TPI or IPI stream header.
        TpiBuilder.setVersionHeader(llvm::pdb::PdbTpiV80);
    }

    void PdbCreator::processGSI(Data::DB &ida_db) {
        auto &GsiBuilder = _pdbBuilder.getGsiBuilder();

        std::vector<llvm::pdb::BulkPublic> Publics;

        //Functions
        for (auto &ida_func : ida_db.Functions()) {
            assert(!ida_func.name.empty());
            Publics.push_back(PdbSymFactory::createPublicSymbol(ida_db.Segments(), ida_func));

            if (_withLabels) {
                for (const auto &ida_label : ida_func.labels) {
                    if (ida_label.is_autonamed) {
                        continue;
                    }

                    Publics.push_back(PdbSymFactory::createPublicSymbol(ida_db.Segments(), ida_label, ida_func));
                }
            }
        }

        //Names
        for (auto &ida_name : ida_db.Names()) {
            assert(!ida_name.name.empty());

            //skip functions because they were already processed
            if (ida_name.is_func) {
                continue;
            }

            Publics.push_back(PdbSymFactory::createPublicSymbol(ida_db.Segments(), ida_name));
        }

        if (!Publics.empty()) {
            // Sort the public symbols and add them to the stream.
            parallelSort(Publics, [](const llvm::pdb::BulkPublic &L, const llvm::pdb::BulkPublic &R) {
                return strcmp(L.Name, R.Name) < 0;
            });

            GsiBuilder.addPublicSymbols(std::move(Publics));
        }
    }

    bool PdbCreator::processSections(Data::DB& ida_db) {
        auto &DbiBuilder = _pdbBuilder.getDbiBuilder();

        // Add Section Map stream.
        std::vector<llvm::object::coff_section> sections;
        for (const auto& segment : ida_db.Segments()) {
            sections.push_back(segment.toLLVM());
        }

        DbiBuilder.createSectionMap(sections);

        // Add COFF section header stream.
        auto sectionsTable = llvm::ArrayRef<uint8_t>(
            reinterpret_cast<const uint8_t*>(sections.data()),
            sections.size()*sizeof(llvm::object::coff_section));
        
        if (DbiBuilder.addDbgStream(llvm::pdb::DbgHeaderType::SectionHdr, sectionsTable)) {
            return false;
        }

        return true;
    }

    void PdbCreator::processSymbols() {
        /*
        auto& DbiBuilder = _pdbBuilder.getDbiBuilder();

        auto& ModuleDBI = DbiBuilder.addModuleInfo("main.obj");
        ModuleDBI->setObjFileName("main.obj");
        uint32_t Modi = ModuleDBI->getModuleIndex();

        llvm::codeview::CVSymbol sym;
        llvm::codeview::CVSymbol::CVRecord()
        sym.kind = llvm::codeview::SymbolKind::S_GPROC32;
        ModuleDBI->addSymbol(sym);
        */
    }
}
