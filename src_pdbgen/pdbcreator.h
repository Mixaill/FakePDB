#pragma once

#include <llvm/Support/Allocator.h>

#include <llvm/DebugInfo/CodeView/SymbolRecord.h>

#include <llvm/DebugInfo/MSF/MSFBuilder.h>

#include <llvm/DebugInfo/PDB/Native/PDBFileBuilder.h>
#include <llvm/DebugInfo/PDB/Native/DbiStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/InfoStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/TpiStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/RawConstants.h>

#include "pefile.h"
#include "idadb.h"

class PdbCreator {
public:

    PdbCreator(PeFile& peFile);

    void Initialize();

    void AddNatvisFile(std::experimental::filesystem::path& path);

    void ImportIDA(IdaDb& ida_db);

    void Commit(std::experimental::filesystem::path& path);

private:
    void addTypeInfo(llvm::pdb::TpiStreamBuilder& TpiBuilder);

    void processGSI(IdaDb& ida_db);

    void processSections();

    llvm::codeview::PublicSym32 createPublicSymbol(IdaFunction& idaFunc);
    llvm::codeview::PublicSym32 createPublicSymbol(IdaName& idaName);

    PeFile& _pefile;

    llvm::BumpPtrAllocator _allocator;
    llvm::pdb::PDBFileBuilder _pdbBuilder;

};