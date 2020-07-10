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

void from_json(const nlohmann::json& j, IdaLabel& l) {
    j.at("offset").get_to(l.offset);
    j.at("name").get_to(l.name);
    j.at("is_public").get_to(l.is_public);
    j.at("is_autonamed").get_to(l.is_autonamed);
}

void from_json(const nlohmann::json& j, IdaFunction& f) {
    j.at("start_rva").get_to(f.start_rva);
    j.at("name").get_to(f.name);
    j.at("is_public").get_to(f.is_public);
    j.at("is_autonamed").get_to(f.is_autonamed);
    j.at("labels").get_to(f.labels);
}

void from_json(const nlohmann::json& j, IdaName& n) {
    j.at("rva").get_to(n.rva);
    j.at("name").get_to(n.name);
    j.at("is_public").get_to(n.is_public);
    j.at("is_func").get_to(n.is_func);
}

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
    _functions = json.at("functions").get<std::vector<IdaFunction>>();

    //Labels
    for (auto &idaFunc : _functions) {
        for (auto &idaLabel : idaFunc.labels) {
            idaLabel.name = idaFunc.name + ":::" + idaLabel.name;
        }
    }

    //Names
    _names = json.at("names").get<std::vector<IdaName>>();
}
