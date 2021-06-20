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
        explicit PeFile(const std::filesystem::path &path);

        [[nodiscard]] std::vector<uint8_t> GetPdbGuid() const;

        [[nodiscard]] uint32_t GetPdbAge() const;

        [[nodiscard]] std::filesystem::path GetPdbFilepath() const;

        [[nodiscard]] std::filesystem::path GetPdbFilename() const;

        [[nodiscard]] llvm::ArrayRef<llvm::object::coff_section> GetSectionHeaders() const;

        [[nodiscard]] uint16_t GetSectionIndexForRVA(uint32_t RVA) const;

        [[nodiscard]] uint32_t GetSectionOffsetForRVA(uint32_t RVA) const;

        [[nodiscard]] uint32_t GetTimestamp() const;

        [[nodiscard]] uint32_t GetImageSize() const;

        [[nodiscard]] std::vector<Data::Export> GetExports() const;

        [[nodiscard]] llvm::COFF::MachineTypes GetMachine() const;

        [[nodiscard]] std::string GetMachineName() const;

        [[nodiscard]] uint32_t GetMachineBitness() const;

    private:

        llvm::Expected<llvm::object::OwningBinary<llvm::object::Binary>> _binary;
        llvm::object::COFFObjectFile *_obj = nullptr;

        std::vector<llvm::object::coff_section> _sectionHeaders;
    };
}
