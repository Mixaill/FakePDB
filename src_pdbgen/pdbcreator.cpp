#include "pdbcreator.h"

#include <llvm/Support/ErrorOr.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/Parallel.h>

#include <llvm/Object/COFF.h>

#include <llvm/DebugInfo/CodeView/SymbolSerializer.h>

#include <llvm/DebugInfo/PDB/Native/DbiModuleDescriptorBuilder.h>
#include <llvm/DebugInfo/PDB/Native/GSIStreamBuilder.h>

template <typename R, class FuncTy> void parallelSort(R&& Range, FuncTy Fn) {
    sort(llvm::parallel::par, std::begin(Range), std::end(Range), Fn);
}

PdbCreator::PdbCreator(PeFile& pefile) : _pefile(pefile),  _pdbBuilder(_allocator)
{
}

void PdbCreator::Initialize()
{
    //initialize builder
    _pdbBuilder.initialize(4096);

    // Create streams in MSF for predefined streams, namely PDB, TPI, DBI and IPI.
    for (int I = 0; I < (int)llvm::pdb::kSpecialStreamCount; ++I) {
        _pdbBuilder.getMsfBuilder().addStream(0);
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
    DbiBuilder.setMachineType(llvm::pdb::PDB_Machine::x86);

    // Technically we are not link.exe 14.11, but there are known cases where
    // debugging tools on Windows expect Microsoft-specific version numbers or
    // they fail to work at all.  Since we know we produce PDBs that are
    // compatible with LINK 14.11, we set that version number here.
    DbiBuilder.setBuildNumber(14, 11);
}

void PdbCreator::AddNatvisFile(std::experimental::filesystem::path& path)
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

    //Sections
    processSections();
}

void PdbCreator::Commit(std::experimental::filesystem::path& path)
{
    _pdbBuilder.commit(path.string(), &_pdbBuilder.getInfoBuilder().getGuid());
}

void PdbCreator::addTypeInfo(llvm::pdb::TpiStreamBuilder& TpiBuilder) {
    // Start the TPI or IPI stream header.
    TpiBuilder.setVersionHeader(llvm::pdb::PdbTpiV80);
}

void PdbCreator::processGSI(IdaDb& ida_db)
{
    auto& GsiBuilder = _pdbBuilder.getGsiBuilder();

    std::vector<llvm::codeview::PublicSym32> Publics;

    //Functions
    for (auto& ida_func : ida_db.Functions()) {
        if (!ida_func.is_public) {
        //    continue;
        }

        Publics.push_back(createPublicSymbol(ida_func));
     
    }

    //Names
    for (auto& ida_name : ida_db.Names()) {
        if (!ida_name.is_public) {
        //    continue;
        }
        
        if (ida_name.is_func) {
            continue;
        }

        Publics.push_back(createPublicSymbol(ida_name));

    }
    
    if (!Publics.empty()) {

        // Sort the public symbols and add them to the stream.
        parallelSort(Publics, [](const llvm::codeview::PublicSym32 & L, const llvm::codeview::PublicSym32 & R) {
            return L.Name < R.Name;
        });

        for (const llvm::codeview::PublicSym32& Pub : Publics) {
            GsiBuilder.addPublicSymbol(Pub);
        }
    }
}

void PdbCreator::processSections()
{
    auto& DbiBuilder = _pdbBuilder.getDbiBuilder();

    // Add Section Map stream.
    auto sections = _pefile.GetSectionHeaders();
    auto SectionMap = llvm::pdb::DbiStreamBuilder::createSectionMap(sections);
    DbiBuilder.setSectionMap(SectionMap);

    // Add COFF section header stream.
    auto sectionsTable = llvm::ArrayRef<uint8_t>(reinterpret_cast<const uint8_t*>(sections.begin()), reinterpret_cast<const uint8_t*>(sections.end()));
    DbiBuilder.addDbgStream(llvm::pdb::DbgHeaderType::SectionHdr, sectionsTable);
}

llvm::codeview::PublicSym32 PdbCreator::createPublicSymbol(IdaFunction& idaFunc)
{
    llvm::codeview::PublicSym32 public_sym;
    public_sym.Name = idaFunc.name;
    public_sym.Flags = llvm::codeview::PublicSymFlags::Function;
    public_sym.Segment = _pefile.GetSectionIndexForRVA(idaFunc.start_ea);
    public_sym.Offset = _pefile.GetSectionOffsetForRVA(idaFunc.start_ea);
   
    return public_sym;
}

llvm::codeview::PublicSym32 PdbCreator::createPublicSymbol(IdaName& idaName)
{
    llvm::codeview::PublicSym32 public_sym;
    public_sym.Name = idaName.name;
    public_sym.Flags = llvm::codeview::PublicSymFlags::None;
    public_sym.Segment = _pefile.GetSectionIndexForRVA(idaName.ea);
    public_sym.Offset = _pefile.GetSectionOffsetForRVA(idaName.ea);

    return public_sym;
}
