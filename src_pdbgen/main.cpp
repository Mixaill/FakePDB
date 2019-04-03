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

#include <iostream>

#include "pdbcreator.h"
#include "idadb.h"

void processInput(const char* filepath) {
    std::cout << filepath << std::endl;
    std::experimental::filesystem::path pathExe(filepath);
    std::experimental::filesystem::path pathJson = pathExe;
    pathJson.replace_extension(".json");

    std::experimental::filesystem::path pathPdb = pathExe;
    pathPdb.replace_extension(".pdb");

    PeFile pefile(pathExe);
    IdaDb ida_db(pathJson);
    PdbCreator creator(pefile);

    creator.Initialize();

    creator.ImportIDA(ida_db);

    creator.Commit(pathPdb);
}

int main(int argc, char* argv[]) {
    if (argc == 0) {
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        processInput(argv[i]);
    }
    
    return 0;
}
