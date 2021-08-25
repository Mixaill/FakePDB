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

//stdlib
#include <limits>
#include <utility>

//fakepdb
#include "segment.h"



namespace FakePDB::Data {

    //
    // Segment
    //

    Segment::Segment(const llvm::object::coff_section& llvm_coff, uint32_t id) {
        
        selector = id;

        name = llvm_coff.Name;

        rva_start = llvm_coff.VirtualAddress;
        rva_end = llvm_coff.VirtualAddress + llvm_coff.VirtualSize;

        align = llvm_coff.getAlignment() * 8;
        
        // IMAGE_SCN_CNT_CODE
        // IMAGE_SCN_CNT_INITIALIZED_DATA
        if ((llvm_coff.Characteristics & llvm::COFF::IMAGE_SCN_CNT_CODE) != 0) {
            type = "CODE";
        }
        else if ((llvm_coff.Characteristics & llvm::COFF::IMAGE_SCN_CNT_INITIALIZED_DATA) != 0) {
            type = "DATA";
        }

        //IMAGE_SCN_MEM_16BIT
        if ((llvm_coff.Characteristics & llvm::COFF::IMAGE_SCN_MEM_16BIT) != 0) {
            bitness = 16;
        }
        else {
            bitness = 32;
        }

        //IMAGE_SCN_MEM_READ
        if ((llvm_coff.Characteristics & llvm::COFF::IMAGE_SCN_MEM_READ) != 0)
        {
            permission += 'R';
        }

        //IMAGE_SCN_MEM_WRITE
        if ((llvm_coff.Characteristics & llvm::COFF::IMAGE_SCN_MEM_WRITE) != 0)
        {
            permission += 'W';
        }

        //IMAGE_SCN_MEM_EXECUTE
        if ((llvm_coff.Characteristics & llvm::COFF::IMAGE_SCN_MEM_EXECUTE) != 0)
        {
            permission += 'X';
        }

        //ignored flags:
        // IMAGE_SCN_LNK_INFO
        // IMAGE_SCN_LNK_REMOVE
        // IMAGE_SCN_LNK_COMDAT
        // IMAGE_SCN_GPREL
        // IMAGE_SCN_LNK_NRELOC_OVFL
        // IMAGE_SCN_MEM_DISCARDABLE 
        // IMAGE_SCN_MEM_NOT_CACHED 
        // IMAGE_SCN_MEM_NOT_PAGED 
        // IMAGE_SCN_MEM_SHARED

    }

    llvm::object::coff_section Segment::toLLVM() const {
        llvm::object::coff_section result{};

        std::memcpy(result.Name, name.c_str(), std::min(sizeof(result.Name) , name.size()));
        
        result.VirtualAddress = rva_start;
        result.VirtualSize = rva_end - rva_start;

        result.Characteristics = 0;

        //IMAGE_SCN_CNT_CODE
        //IMAGE_SCN_CNT_INITIALIZED_DATA
        if (type == "CODE") {
            result.Characteristics |= llvm::COFF::IMAGE_SCN_CNT_CODE;
        }
        else if (type == "DATA") {
            result.Characteristics |= llvm::COFF::IMAGE_SCN_CNT_INITIALIZED_DATA;       
        }
        
        //IMAGE_SCN_MEM_16BIT
        if (bitness == 16) {
            result.Characteristics |= llvm::COFF::IMAGE_SCN_MEM_16BIT;
        }

        //IMAGE_SCN_MEM_16BIT
        if (bitness == 16) {
            result.Characteristics |= llvm::COFF::IMAGE_SCN_MEM_16BIT;
        }

        for (char i : permission) {
            //IMAGE_SCN_MEM_READ
            if (i == 'R') {
                result.Characteristics |= llvm::COFF::IMAGE_SCN_MEM_READ;
            }

            //IMAGE_SCN_MEM_WRITE
            if (i == 'W') {
                result.Characteristics |= llvm::COFF::IMAGE_SCN_MEM_WRITE;
            }

            //IMAGE_SCN_MEM_EXECUTE
            if (i == 'X') {
                result.Characteristics |= llvm::COFF::IMAGE_SCN_MEM_EXECUTE;
            }
        }

        return result;
    }


    //
    // Segment Array
    //

    uint32_t SegmentArray::getSectionIndexByRva(uint32_t rva) const {
        for (auto &section : *this) {
            if (section.rva_start <= rva && section.rva_end >= rva) {
                return section.selector;
            }
        }

        return 0;
    }

    uint32_t SegmentArray::getSectionBaseByIndex(uint32_t sectionIndex) const {
        uint32_t sectionBase = std::numeric_limits<std::uint32_t>::max();
        for (auto &section : *this) {
            if (section.selector == sectionIndex) {
                sectionBase = std::min(sectionBase, section.rva_start);
            }
        }

        return sectionBase;
    }

    uint32_t SegmentArray::getSectionOffsetByRva(uint32_t rva) const {
        uint32_t sectionIndex = getSectionIndexByRva(rva);
        if(!sectionIndex){
            return 0;
        }

        uint32_t sectionBase = getSectionBaseByIndex(sectionIndex);

        return rva - sectionBase;
    }
}
