#pragma once

//stdlib
#include <string>

//nlohmann
#include "nlohmann/json.hpp"

//fakepdb
#include "data/general.h"
#include "data/export.h"
#include "data/function.h"
#include "data/name.h"
#include "data/segment.h"

namespace FakePDB::Data {
    struct Root {
        SectionGeneral general;
        std::vector<Segment> segments;
        std::vector<Export> exports;
        std::vector<Function> functions;
        std::vector<Name> names;
    };

    inline void to_json(nlohmann::json &nlohmann_json_j, const Root &nlohmann_json_t) {
        nlohmann_json_j["general"] = nlohmann_json_t.general;
        nlohmann_json_j["segments"] = nlohmann_json_t.segments;
        nlohmann_json_j["exports"] = nlohmann_json_t.exports;
        nlohmann_json_j["functions"] = nlohmann_json_t.functions;
        nlohmann_json_j["names"] = nlohmann_json_t.names;
    }

    inline void from_json(const nlohmann::json &nlohmann_json_j, Root &nlohmann_json_t) {
        if(nlohmann_json_j.contains("general")) {
            nlohmann_json_j.at("general").get_to(nlohmann_json_t.general);
        }

        if(nlohmann_json_j.contains("segments")){
            nlohmann_json_j.at("segments").get_to(nlohmann_json_t.segments);
        }

        if(nlohmann_json_j.contains("exports")) {
            nlohmann_json_j.at("exports").get_to(nlohmann_json_t.exports);
        }

        if(nlohmann_json_j.contains("functions")) {
            nlohmann_json_j.at("functions").get_to(nlohmann_json_t.functions);
        }

        if(nlohmann_json_j.contains("names")) {
            nlohmann_json_j.at("names").get_to(nlohmann_json_t.names);
        }
    }
}
