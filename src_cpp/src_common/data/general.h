#pragma once

//stdlib
#include <cstdint>
#include <string>

//nlohmann
#include "nlohmann/json.hpp"

//llvm
#include <llvm/Object/COFF.h>

//fakepdb
#include "label.h"

namespace FakePDB::Data {
    struct SectionGeneral {
        std::string filename;
        std::string architecture;
        uint32_t bitness;

        [[nodiscard]] bool empty() const{
            return filename.empty();
        }

        [[nodiscard]] llvm::COFF::MachineTypes getMachineType() const {
            if(architecture == "x86" && bitness == 64) {
                return llvm::COFF::IMAGE_FILE_MACHINE_AMD64;
            }

            if(architecture == "x86" && bitness == 32) {
                return llvm::COFF::IMAGE_FILE_MACHINE_I386;
            }

            if(architecture == "arm" && bitness == 64) {
                return llvm::COFF::IMAGE_FILE_MACHINE_ARM64;
            }

            if(architecture == "arm" && bitness == 32) {
                return llvm::COFF::IMAGE_FILE_MACHINE_ARMNT;
            }

            return llvm::COFF::IMAGE_FILE_MACHINE_UNKNOWN;
        }
    };

    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(SectionGeneral, filename, architecture, bitness)
}
