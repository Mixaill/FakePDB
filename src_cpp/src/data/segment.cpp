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
#include <cstdint>
#include <limits>
#include <utility>

//fakepdb
#include "data/segment.h"

namespace FakePDB::Data {
    uint32_t SegmentArray::getSectionIndexByRva(uint32_t rva) const {
        for (auto &section : *this) {
            if (section.start_rva <= rva && section.end_rva >= rva) {
                return section.selector;
            }
        }

        return 0;
    }

    uint32_t SegmentArray::getSectionBaseByIndex(uint32_t sectionIndex) const {
        uint32_t sectionBase = std::numeric_limits<std::uint32_t>::max();
        for (auto &section : *this) {
            if (section.selector == sectionIndex) {
                sectionBase = std::min(sectionBase, section.start_rva);
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
