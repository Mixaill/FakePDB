#include "idadb.h"

#include "nlohmann/json.hpp"

#include <fstream>

IdaDb::IdaDb(std::experimental::filesystem::path& filepath)
{
    load(filepath);
}

std::vector<IdaFunction>& IdaDb::Functions()
{
    return _functions;
}

std::vector<IdaName>& IdaDb::Names()
{
    return _names;
}

void IdaDb::load(std::experimental::filesystem::path& filepath)
{
    std::ifstream istream(filepath);
    nlohmann::json json;
    istream >> json;

    //Function
    _functions.clear();
    auto& functions = json["functions"];
    for (auto& function : functions) {
        IdaFunction idaf{};
        idaf.name = function["name"].get<std::string>();
        idaf.is_autonamed = function["is_autonamed"].get<bool>();
        idaf.is_public = function["is_public"].get<bool>();
        idaf.start_ea = function["start_ea"].get<uint32_t>();

        _functions.push_back(idaf);
    }

    //Names
    _names.clear();
    auto& names = json["names"];
    for (auto& name : names) {
        IdaName idan{};
        idan.name = name["name"].get<std::string>();
        idan.is_func = name["is_func"].get<bool>();
        idan.is_public = name["is_public"].get<bool>();
        idan.ea = name["ea"].get<uint32_t>();
        
        _names.push_back(idan);
    }
}
