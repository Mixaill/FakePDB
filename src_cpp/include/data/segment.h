#pragma once

//stdlib
#include <cstdint>
#include <string>

//nlohmann
#include "nlohmann/json.hpp"

namespace FakePDB::Data {
    struct Segment {
        std::string name;
        uint32_t start_rva;
        uint32_t end_rva;
        std::string type;
        uint32_t selector;
    };

    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Segment, name, start_rva, end_rva, type, selector)
}
