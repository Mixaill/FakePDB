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

#include "idadb.h"

#include "nlohmann/json.hpp"

#include <fstream>

IdaDb::IdaDb(std::filesystem::path& filepath)
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

void IdaDb::load(std::filesystem::path& filepath)
{
    std::ifstream istream(filepath);
	if (!istream.is_open()) {
		return;
	}
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
        idaf.start_ea = function["start_ea"].get<uint64_t>();

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
        idan.ea = name["ea"].get<uint64_t>();
        
        _names.push_back(idan);
    }
}
