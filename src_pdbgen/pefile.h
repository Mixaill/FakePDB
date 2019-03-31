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