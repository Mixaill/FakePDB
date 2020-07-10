/**
   Copyright 2019 LLVM project
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

#include "pdbcreator.h"

#include <llvm/Support/ErrorOr.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/Parallel.h>

#include <llvm/Object/COFF.h>

#include <llvm/DebugInfo/CodeView/SymbolSerializer.h>

#include <llvm/DebugInfo/PDB/Native/DbiModuleDescriptorBuilder.h>

template <typename R, class FuncTy> void parallelSort(R&& Range, FuncTy Fn) {
    llvm::parallelSort(std::begin(Range), std::end(Range), Fn);
}

PdbCreator::PdbCreator(PeFile& pefile) : _pefile(pefile),  _pdbBuilder(_allocator)
{
}

bool PdbCreator::Initialize()
{
    //initialize builder
    if (_pdbBuilder.initialize(4096)) {
        return false;
    }
    
    // Create streams in MSF for predefined streams, namely PDB, TPI, DBI and IPI.
    for (int I = 0; I < (int)llvm::pdb::kSpecialStreamCount; ++I) {
        if (_pdbBuilder.getMsfBuilder().addStream(0).takeError()) {
            return false;
        }
    }

    // Add an Info stream.
    auto& InfoBuilder = _pdbBuilder.getInfoBuilder();
    InfoBuilder.setVersion(llvm::pdb::PdbRaw_ImplVer::PdbImplVC70);
    InfoBuilder.setHashPDBContentsToGUID(false);
    InfoBuilder.setAge(_pefile.GetPdbAge());

    auto guid_d = _pefile.GetPdbGuid();
    llvm::codeview::GUID guid{};
    memcpy(guid.Guid, guid_d.data(), guid_d.size());
    InfoBuilder.setGuid(guid);

    //Add an empty DBI stream.
    auto& DbiBuilder = _pdbBuilder.getDbiBuilder();
    DbiBuilder.setAge(InfoBuilder.getAge());
    DbiBuilder.setVersionHeader(llvm::pdb::PdbDbiV70);
    DbiBuilder.setMachineType(_pefile.GetMachine());
    DbiBuilder.setFlags(llvm::pdb::DbiFlags::FlagStrippedMask);

    // Technically we are not link.exe 14.11, but there are known cases where
    // debugging tools on Windows expect Microsoft-specific version numbers or
    // they fail to work at all.  Since we know we produce PDBs that are
    // compatible with LINK 14.11, we set that version number here.
    DbiBuilder.setBuildNumber(14, 11);

    return true;
}

void PdbCreator::AddNatvisFile(std::filesystem::path& path)
{
    llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> DataOrErr = llvm::MemoryBuffer::getFile(path.string());
    _pdbBuilder.addInjectedSource(path.string(), std::move(*DataOrErr));
}

void PdbCreator::ImportIDA(IdaDb& ida_db)
{
    //TPI
    addTypeInfo(_pdbBuilder.getTpiBuilder());

    //IPI
    addTypeInfo(_pdbBuilder.getIpiBuilder());

    //GSI
    processGSI(ida_db);

    //Symbols
    processSymbols();

    //Sections
    processSections();
}

bool PdbCreator::Commit(std::filesystem::path& path)
{
	std::filesystem::create_directories(path.parent_path());
    if (_pdbBuilder.commit(path.string(), &_pdbBuilder.getInfoBuilder().getGuid())) {
        return false;
    }

    return true;
}

void PdbCreator::addTypeInfo(llvm::pdb::TpiStreamBuilder& TpiBuilder) {
    // Start the TPI or IPI stream header.
    TpiBuilder.setVersionHeader(llvm::pdb::PdbTpiV80);
}

void PdbCreator::processGSI(IdaDb& ida_db)
{
    auto& GsiBuilder = _pdbBuilder.getGsiBuilder();

    std::vector<llvm::pdb::BulkPublic> Publics;

    //Functions
    for (auto& ida_func : ida_db.Functions()) {
        Publics.push_back(createPublicSymbol(ida_func));
    }

    //Names
    for (auto& ida_name : ida_db.Names()) {

        //skip functions because they were already processed
        if (ida_name.is_func) {
            continue;
        }

        Publics.push_back(createPublicSymbol(ida_name));
    }
    
    if (!Publics.empty()) {

        // Sort the public symbols and add them to the stream.
        parallelSort(Publics, [](const llvm::pdb::BulkPublic& L, const llvm::pdb::BulkPublic& R) {
            return strcmp(L.Name, R.Name);
        });

        GsiBuilder.addPublicSymbols(std::move(Publics));
    }
}

bool PdbCreator::processSections()
{
    auto& DbiBuilder = _pdbBuilder.getDbiBuilder();

    // Add Section Map stream.
    auto sections = _pefile.GetSectionHeaders();
    DbiBuilder.createSectionMap(sections);

    // Add COFF section header stream.
    auto sectionsTable = llvm::ArrayRef<uint8_t>(reinterpret_cast<const uint8_t*>(sections.begin()), reinterpret_cast<const uint8_t*>(sections.end()));
    if (DbiBuilder.addDbgStream(llvm::pdb::DbgHeaderType::SectionHdr, sectionsTable)) {
        return false;
    }

    return true;
}

void PdbCreator::processSymbols()
{
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

llvm::pdb::BulkPublic PdbCreator::createPublicSymbol(IdaFunction& idaFunc)
{
    llvm::pdb::BulkPublic public_sym;
    public_sym.Name = idaFunc.name.c_str();
    public_sym.NameLen = idaFunc.name.size();
    public_sym.setFlags(llvm::codeview::PublicSymFlags::Function);
    public_sym.Segment = _pefile.GetSectionIndexForEA(idaFunc.start_ea);
    public_sym.Offset = _pefile.GetSectionOffsetForEA(idaFunc.start_ea);

    return public_sym;
}

llvm::pdb::BulkPublic PdbCreator::createPublicSymbol(IdaName& idaName)
{
    llvm::pdb::BulkPublic public_sym;
    public_sym.Name = idaName.name.c_str();
    public_sym.NameLen = idaName.name.size();
    public_sym.setFlags(llvm::codeview::PublicSymFlags::None);
    public_sym.Segment = _pefile.GetSectionIndexForEA(idaName.ea);
    public_sym.Offset = _pefile.GetSectionOffsetForEA(idaName.ea);

    return public_sym;
}
