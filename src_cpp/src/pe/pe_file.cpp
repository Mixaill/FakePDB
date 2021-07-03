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

//LLVM
#include <llvm/Support/Error.h>

//FakePDB
#include "pe/pe_file.h"

namespace FakePDB::PE {
    PeFile::PeFile(const std::filesystem::path& path) : _binary(llvm::object::createBinary(path.string()))
    {
        if (!_binary.takeError()) {
            _obj = llvm::dyn_cast<llvm::object::COFFObjectFile>((*_binary).getBinary());
        }
    }

    std::vector<uint8_t> PeFile::GetPdbGuid() const
    {
        const llvm::codeview::DebugInfo* DebugInfo;
        llvm::StringRef PDBFileName;

        if(_obj->getDebugPDBInfo(DebugInfo, PDBFileName) ||!DebugInfo){
            return std::vector<uint8_t>(16);
        }

        return std::vector<uint8_t>(&DebugInfo->PDB70.Signature[0], &DebugInfo->PDB70.Signature[16]);
    }

    uint32_t PeFile::GetPdbAge() const
    {
        const llvm::codeview::DebugInfo* DebugInfo = nullptr;
        llvm::StringRef PDBFileName;

        if(_obj->getDebugPDBInfo(DebugInfo, PDBFileName) || !DebugInfo){
            return 0;
        }

        return DebugInfo->PDB70.Age;
    }

    std::filesystem::path PeFile::GetPdbFilepath() const
    {
        const llvm::codeview::DebugInfo* DebugInfo;
        llvm::StringRef PDBFileName;

        if(_obj->getDebugPDBInfo(DebugInfo, PDBFileName)){
            return "";
        }

        return std::filesystem::path(std::string(PDBFileName));
    }

    std::filesystem::path PeFile::GetPdbFilename() const
    {
        return GetPdbFilepath().filename();
    }

    llvm::ArrayRef<llvm::object::coff_section> PeFile::GetSectionHeaders() const
    {
        const auto number_of_sections = _obj->getNumberOfSections();
        const auto* section = _obj->getCOFFSection(*_obj->sections().begin());

        return llvm::ArrayRef<llvm::object::coff_section>(section, number_of_sections);
    }


    uint16_t PeFile::GetSectionIndexForRVA(uint32_t RVA) const
    {
        uint16_t index = 1;
        for (auto& section : GetSectionHeaders()) {
            if (section.VirtualAddress <= RVA && section.VirtualAddress + section.VirtualSize >= RVA) {
                return index;
            }

            index++;
        }

        return 0;
    }

    uint32_t PeFile::GetSectionOffsetForRVA(uint32_t RVA) const
    {
        for (auto& section : GetSectionHeaders()) {
            if (section.VirtualAddress <= RVA && section.VirtualAddress + section.VirtualSize >= RVA) {
                return RVA - section.VirtualAddress;
            }
        }

        return 0;
    }

    uint32_t PeFile::GetTimestamp() const
    {
        return _obj->getTimeDateStamp();
    }

    uint32_t PeFile::GetImageSize() const
    {
        auto* pe32 = _obj->getPE32Header();
        if (pe32) {
            return pe32->SizeOfImage;
        }

        auto* pe32plus = _obj->getPE32PlusHeader();
        if (pe32plus) {
            return pe32plus->SizeOfImage;
        }

        return 0;
    }

    std::vector<Data::Export> PeFile::GetExports() const
    {
        std::vector<Data::Export> result;

        for (const llvm::object::ExportDirectoryEntryRef& exp : _obj->export_directories()) {

            Data::Export entry{};

            llvm::StringRef name;
            if (exp.getSymbolName(name)) {
                continue;
            }
            entry.name = std::string(name);

            if (exp.getExportRVA(entry.rva)) {
                continue;
            }
            if (exp.getOrdinal(entry.ordinal)) {
                continue;
            }

            result.push_back(entry);
        }

        return result;
    }

    llvm::COFF::MachineTypes PeFile::GetMachine() const {
        return static_cast<llvm::COFF::MachineTypes>(_obj->getMachine());
    }

    uint32_t PeFile::GetMachineBitness() const {
        switch(GetMachine()){
            case llvm::COFF::IMAGE_FILE_MACHINE_ARM:
            case llvm::COFF::IMAGE_FILE_MACHINE_ARMNT:
            case llvm::COFF::IMAGE_FILE_MACHINE_I386:
                return 32;
            case llvm::COFF::IMAGE_FILE_MACHINE_ARM64:
            case llvm::COFF::IMAGE_FILE_MACHINE_AMD64:
            case llvm::COFF::IMAGE_FILE_MACHINE_IA64:
                return 64;
            default:
                return 0;
        }
    }

    std::string PeFile::GetMachineName() const {
        switch(GetMachine()){
            case llvm::COFF::IMAGE_FILE_MACHINE_ARM:
            case llvm::COFF::IMAGE_FILE_MACHINE_ARMNT:
            case llvm::COFF::IMAGE_FILE_MACHINE_ARM64:
                return "arm";
            case llvm::COFF::IMAGE_FILE_MACHINE_I386:
            case llvm::COFF::IMAGE_FILE_MACHINE_AMD64:
                return "x86";
            case llvm::COFF::IMAGE_FILE_MACHINE_IA64:
                return "ia64";
            default:
                return "unknown";
        }
    }

    Data::SegmentArray PeFile::GetSections() const {
        Data::SegmentArray result;

        auto sections = GetSectionHeaders();
        for(uint32_t i = 0; i < sections.size(); i++){
            Data::Segment seg = {
                    .name = sections[i].Name,
                    .start_rva = sections[i].VirtualAddress,
                    .end_rva = sections[i].VirtualAddress + sections[i].VirtualSize,
                    .selector = i + 1
            };

            result.push_back(seg);
        }

        return result;
    }
}