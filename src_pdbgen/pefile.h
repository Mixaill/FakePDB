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

#include <cstdint>
#include <filesystem>
#include <string>

#include <llvm/ADT/ArrayRef.h>

#include <llvm/Object/Binary.h>
#include <llvm/Object/COFF.h>

class PeFile {
public:
    PeFile(std::experimental::filesystem::path& path);

    std::vector<uint8_t> GetPdbGuid();
    uint32_t GetPdbAge();
    std::string GetPdbFilepath();

    llvm::ArrayRef<llvm::object::coff_section> GetSectionHeaders();

    uint16_t GetSectionIndexForRVA(uint32_t RVA);

    uint32_t GetSectionOffsetForRVA(uint32_t RVA);

private:
    
    llvm::Expected<llvm::object::OwningBinary<llvm::object::Binary>> _binary;
    llvm::object::COFFObjectFile* _obj;

    std::vector<llvm::object::coff_section> _sectionHeaders;

};