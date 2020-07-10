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

#pragma once

#include <cstdint>
#include <filesystem>
#include <vector>

struct IdaFunction {
    std::string name;
    uint64_t start_ea;
    bool is_public;
    bool is_autonamed;
};

struct IdaName {
    uint64_t ea;
    std::string name;
    bool is_public;
    bool is_func;
};

class IdaDb {
public:
    explicit IdaDb(std::filesystem::path& filepath);
    std::vector<IdaFunction>& Functions();
    std::vector<IdaName>& Names();
private:
    void load(std::filesystem::path& filepath);

    std::vector<IdaFunction> _functions;
    std::vector<IdaName> _names;
};