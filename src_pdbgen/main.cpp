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

#include <filesystem>
#include <iostream>

#include "pdbcreator.h"
#include "guidhelper.h"
#include "hexhelper.h"
#include "idadb.h"

void processInput(const char* filepath) {
    std::cout << filepath << std::endl;
    std::filesystem::path pathExe(filepath);
	if (!std::filesystem::exists(pathExe)) {
		std::cerr << ".exe file does not exists";
		return;
	}

	std::filesystem::path pathJson = pathExe;
	pathJson += ".json";
	if (!std::filesystem::exists(pathJson)) {
		std::cerr << ".exe file does not exists";
		return;
	}

    PeFile pefile(pathExe);
    IdaDb ida_db(pathJson);
    PdbCreator creator(pefile);

    creator.Initialize();

    creator.ImportIDA(ida_db);

	auto pathPdb = pathExe.parent_path() / "output"  / pathExe.filename().replace_extension(".pdb") / (guidToHex(pefile.GetPdbGuid()) + std::to_string(pefile.GetPdbAge())) / pathExe.filename().replace_extension(".pdb");
    creator.Commit(pathPdb);

	auto pathExeOut = pathExe.parent_path() / "output" / pathExe.filename() / (intToHex(pefile.GetTimestamp())+intToHex(pefile.GetImageSize())) / pathExe.filename();
	std::filesystem::create_directories(pathExeOut.parent_path());
	std::filesystem::copy_file(pathExe, pathExeOut, std::filesystem::copy_options::overwrite_existing);
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
