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

#include "pefile.h"


#include <llvm/Support/Error.h>

PeFile::PeFile(std::filesystem::path& path) : _binary(llvm::object::createBinary(path.string()))
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
	const llvm::codeview::DebugInfo* DebugInfo = nullptr;
    llvm::StringRef PDBFileName;

    _obj->getDebugPDBInfo(DebugInfo, PDBFileName);
	if (DebugInfo == nullptr) {
		return 0;
	}

    return DebugInfo->PDB70.Age;
}

std::filesystem::path PeFile::GetPdbFilepath()
{
    const llvm::codeview::DebugInfo* DebugInfo;
    llvm::StringRef PDBFileName;

    _obj->getDebugPDBInfo(DebugInfo, PDBFileName);
    return std::filesystem::path(std::string(PDBFileName));
}

std::filesystem::path PeFile::GetPdbFilename()
{
    return GetPdbFilepath().filename();
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

uint32_t PeFile::GetTimestamp()
{
	return _obj->getTimeDateStamp();
}

uint32_t PeFile::GetImageSize()
{
	const llvm::object::pe32_header* pe32 = nullptr;
	_obj->getPE32Header(pe32);
	return pe32->SizeOfImage;
}


llvm::COFF::MachineTypes PeFile::GetMachine()
{
    return static_cast<llvm::COFF::MachineTypes>(_obj->getMachine());
}
