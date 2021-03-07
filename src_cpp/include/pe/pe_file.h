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

#pragma once

//stdlib
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

//LLVM
#include <llvm/ADT/ArrayRef.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/COFF.h>

//fakepdb
#include "data/export.h"

namespace FakePDB::PE {
    class PeFile {
    public:
        PeFile(const std::filesystem::path &path);

        std::vector<uint8_t> GetPdbGuid();

        uint32_t GetPdbAge();

        std::filesystem::path GetPdbFilepath();

        std::filesystem::path GetPdbFilename();

        llvm::ArrayRef<llvm::object::coff_section> GetSectionHeaders();

        uint16_t GetSectionIndexForRVA(uint32_t RVA);

        uint32_t GetSectionOffsetForRVA(uint32_t RVA);

        uint32_t GetTimestamp();

        uint32_t GetImageSize();

        std::vector<Data::Export> GetExports();

        llvm::COFF::MachineTypes GetMachine();

        std::string GetMachineName();

        uint32_t GetMachineBitness();

    private:

        llvm::Expected<llvm::object::OwningBinary<llvm::object::Binary>> _binary;
        llvm::object::COFFObjectFile *_obj;

        std::vector<llvm::object::coff_section> _sectionHeaders;

    };
}
