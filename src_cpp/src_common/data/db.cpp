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

//stdlib
#include <fstream>

//nlohmann
#include "nlohmann/json.hpp"

//fakepdb
#include "db.h"

namespace FakePDB::Data {
    DB::DB(){

    }

    DB::DB(std::filesystem::path &filepath) {
        load(filepath);
    }

    SectionGeneral& DB::General(){
        return _root.general;
    }

    SectionPE& DB::PE(){
        return _root.pe;
    }

    SegmentArray& DB::Segments(){
        return _root.segments;
    }

    std::vector<Export> &DB::Exports() {
        return _root.exports;
    }

    std::vector<Function> &DB::Functions() {
        return _root.functions;
    }

    std::vector<Name> &DB::Names() {
        return _root.names;
    }

    void DB::load(std::filesystem::path &filepath) {
        std::ifstream istream(filepath);
        if (!istream.is_open()) {
            return;
        }

        nlohmann::json json;
        istream >> json;
        _root = json.get<Root>();

        //Labels
        for (auto &idaFunc : _root.functions) {
            for (auto &idaLabel : idaFunc.labels) {
                idaLabel.name = idaFunc.name + ":::" + idaLabel.name;
            }
        }
    }

    void DB::Save(std::filesystem::path &filepath) {
        nlohmann::json json = _root;
        std::ofstream file(filepath);
        file << std::setw(4) << json;
    }
}
