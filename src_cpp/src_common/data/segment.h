#pragma once

//stdlib
#include <cstdint>
#include <string>
#include <vector>

//nlohmann
#include "nlohmann/json.hpp"

//llvm
#include <llvm/Object/COFF.h>

namespace FakePDB::Data {
    struct Segment {
        /**
         * Segment alignment in bits
         */
        uint32_t align;

        /**
         * Number of bits in the segment addressing
         */
        uint32_t bitness;

        /**
         * Segment name
         */
        std::string name;

        /**
         * Segment start address relative to image bases
         */
        uint32_t rva_start;
      
        /**
         * Segment end address relative to image bases
         */
        uint32_t rva_end;

        /**
         * Segment permission
         * 
         * @note: possible value is combination of R,W,X
         */
        std::string permission;

        /**
         * Unique selector of segment
         */
        uint32_t selector;

        /**
         * Type of the segment
         * @note possible values: CODE , DATA
         */
        std::string type;

        explicit Segment() = default;
        explicit Segment(const llvm::object::coff_section& llvm_coff, uint32_t id);

        llvm::object::coff_section toLLVM() const;
    };

    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Segment, align, bitness, name, rva_start, rva_end, permission, selector, type)

    class SegmentArray : public std::vector<Segment> {
    public:
        [[nodiscard]] uint32_t getSectionIndexByRva(uint32_t rva) const;
        [[nodiscard]] uint32_t getSectionBaseByIndex(uint32_t sectionIndex) const;
        [[nodiscard]] uint32_t getSectionOffsetByRva(uint32_t rva) const;
    };
}
