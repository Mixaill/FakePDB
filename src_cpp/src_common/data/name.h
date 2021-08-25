#pragma once

//stdlib
#include <cstdint>
#include <string>

//nlohmann
#include "nlohmann/json.hpp"

namespace FakePDB::Data {
    struct Name {
        uint32_t rva;
        std::string name;
        bool is_public;
        bool is_func;
    };

    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Name, rva, name, is_public, is_func)
}