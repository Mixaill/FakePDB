/**
   Copyright 2019-2020 Mikhail Paulyshka

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


int main_usage(){
    std::cout << "PDB generator" << std::endl << "Usage:" << std::endl 
    << "* pdbgen symserv_exe <exe filepath> -- returns EXE folder name for symbol server" << std::endl
    << "* pdbgen symserv_pdb <exe filepath> -- returns PDB folder name for symbol server" << std::endl
    << "* pdbgen generate [-l] <exe filepath> <json filepath> <output file> -- generate PDB file for given file" << std::endl;
    return 0;
}


int main_symserv_exe(int argc, char* argv[]){
    std::string pathExe = argv[2];

    if (!std::filesystem::exists(pathExe)) {
		std::cerr << ".exe file does not exists";
		return 1;
	}

    PeFile pefile(pathExe);

    std::cout << (intToHex(pefile.GetTimestamp())+intToHex(pefile.GetImageSize()));
    return 0;
}


int main_symserv_pdb(int argc, char* argv[]){
    std::string pathExe = argv[2];

    if (!std::filesystem::exists(pathExe)) {
		std::cerr << ".exe file does not exists";
		return 1;
	}

    PeFile pefile(pathExe);

    std::cout << (guidToHex(pefile.GetPdbGuid()) + intToHex(pefile.GetPdbAge()));
    return 0;
}


int main_generate(int argc, char* argv[]) {
    bool with_labels = false;
    size_t arg_exe = 2;
    if (argc > 5 && std::string(argv[2]) == "-l") {
        arg_exe++;
        with_labels = true;
    }
    std::filesystem::path path_exe  = argv[arg_exe];
    std::filesystem::path path_json = argv[arg_exe+1];
    std::filesystem::path path_out  = argv[arg_exe+2];

    if (!std::filesystem::exists(path_exe)) {
		std::cerr << ".exe file does not exists";
		return 2;
	}

    if (!std::filesystem::exists(path_json)) {
		std::cerr << ".json file does not exists";
		return 3;
	}

    PeFile pefile(path_exe);
    IdaDb ida_db(path_json);
    PdbCreator creator(pefile, with_labels);

    creator.Initialize();
    creator.ImportIDA(ida_db);
    
    std::filesystem::create_directories(path_out.parent_path());
    creator.Commit(path_out);

    return 0;
}


int main(int argc, char* argv[]) {
    if (argc > 1) {
        if(argc > 2 && !stricmp(argv[1], "symserv_exe")){
            return main_symserv_exe(argc, argv);
        }
        else if(argc > 2 && !stricmp(argv[1], "symserv_pdb")){
            return main_symserv_pdb(argc, argv);
        }
        else if(argc > 4 && !stricmp(argv[1], "generate")){
            return main_generate(argc, argv);
        }
    }
    
    return main_usage();
}
