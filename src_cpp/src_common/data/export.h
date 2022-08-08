#pragma once

//stdlib
#include <string>

//Nlohmann
#include "nlohmann/json.hpp"

namespace FakePDB::Data {
    struct Export {
        uint32_t ordinal;
        uint32_t rva;
        std::string name;

        /**
         * Possible values:
         *  - unknown
         *  - function
         *  - data
         */
        std::string type;

        std::string calling_convention;
    };

    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Export, ordinal, rva, name)
}
