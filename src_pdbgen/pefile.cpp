#include "pefile.h"


#include <llvm/Support/Error.h>

PeFile::PeFile(std::experimental::filesystem::path& path) : _binary(llvm::object::createBinary(path.string()))
{
    _obj = llvm::dyn_cast<llvm::object::COFFObjectFile>(_binary.get().getBinary());
}

std::vector<uint8_t> PeFile::GetPdbGuid()
{
    const llvm::codeview::DebugInfo* DebugInfo;
    llvm::StringRef PDBFileName;

    _obj->getDebugPDBInfo(DebugInfo, PDBFileName);
    return std::vector<uint8_t>(&DebugInfo->PDB70.Signature[0], &DebugInfo->PDB70.Signature[16]);
}

uint32_t PeFile::GetPdbAge()
{
    const llvm::codeview::DebugInfo* DebugInfo;
    llvm::StringRef PDBFileName;

    _obj->getDebugPDBInfo(DebugInfo, PDBFileName);
    return DebugInfo->PDB70.Age;
}

std::string PeFile::GetPdbFilepath()
{
    const llvm::codeview::DebugInfo* DebugInfo;
    llvm::StringRef PDBFileName;

    _obj->getDebugPDBInfo(DebugInfo, PDBFileName);
    return std::string(PDBFileName);
}

llvm::ArrayRef<llvm::object::coff_section> PeFile::GetSectionHeaders()
{
    auto number_of_sections = _obj->getNumberOfSections();
    const llvm::object::coff_section* section = nullptr;

    for (const llvm::object::SectionRef& Sec : _obj->sections()) {
        section = _obj->getCOFFSection(Sec);
        break;
    }

    return llvm::ArrayRef<llvm::object::coff_section>(section,number_of_sections);
}

uint16_t PeFile::GetSectionIndexForRVA(uint32_t RVA)
{
    RVA -= _obj->getImageBase();

    uint16_t index = 1;
    for (auto& section : GetSectionHeaders()) {
        uint32_t s_va = section.VirtualAddress;
        if (section.VirtualAddress <= RVA && section.VirtualAddress + section.VirtualSize >= RVA) {
            return index;
        }
        
        index++;
    }

    return 0;
}

uint32_t PeFile::GetSectionOffsetForRVA(uint32_t RVA)
{
    RVA -= _obj->getImageBase();

    for (auto& section : GetSectionHeaders()) {
        if (section.VirtualAddress <= RVA && section.VirtualAddress + section.VirtualSize >= RVA) {
            return RVA - section.VirtualAddress;
        }
    }

    return 0;
}
