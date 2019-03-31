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
