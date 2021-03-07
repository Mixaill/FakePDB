#pragma once

//stdlib
#include <cstdint>
#include <string>

//nlohmann
#include "nlohmann/json.hpp"

//fakepdb
#include "data/label.h"

namespace FakePDB::Data {
    struct General {
        std::string filename;
        std::string architecture;
        uint32_t bitness;

        [[nodiscard]] bool empty() const{
            return filename.empty();
        }
    };

    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(General, filename, architecture, bitness)
}
