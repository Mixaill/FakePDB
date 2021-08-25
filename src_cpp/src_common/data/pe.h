#pragma once

//stdlib
#include <array>
#include <cstdint>
#include <string>

//Nlohmann
#include "nlohmann/json.hpp"

namespace FakePDB::Data {
    struct SectionPE {
        uint32_t image_datetime;
        uint16_t image_machine;
        uint32_t image_size;

        uint32_t pdb_age;
        std::array<uint8_t, 16> pdb_guid;
    };

    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(SectionPE, image_datetime, image_size, pdb_age, pdb_guid)
}
