#pragma once

//stdlib
#include <cstdint>
#include <string>

//nlohmann
#include "nlohmann/json.hpp"

namespace FakePDB::Data {
    struct Label {
        uint32_t offset;
        std::string name;
        bool is_public;
        bool is_autonamed;
    };

    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Label, offset, name, is_public, is_autonamed)
}
