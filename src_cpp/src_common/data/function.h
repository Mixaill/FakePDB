#pragma once

//stdlib
#include <cstdint>
#include <string>
#include <vector>

//nlohmann
#include "nlohmann/json.hpp"

//fakepdb
#include "label.h"

namespace FakePDB::Data {
    struct Function {
        std::string name;
        uint32_t start_rva;
        bool is_public;
        bool is_autonamed;
        std::vector<Label> labels;
    };

    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Function, start_rva, name, is_public, is_autonamed, labels)
}
