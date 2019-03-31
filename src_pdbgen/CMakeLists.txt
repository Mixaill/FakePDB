cmake_minimum_required(VERSION 3.4.3)
project(PDBGenLLVM)

find_package(LLVM REQUIRED CONFIG)

include_directories(${LLVM_INCLUDE_DIRS})

set(PDBGEN_SOURCES
    main.cpp

    pefile.cpp
    pefile.h

    idadb.cpp
    idadb.h

    pdbcreator.cpp
    pdbcreator.h
)

add_executable(pdbgen ${PDBGEN_SOURCES})

target_include_directories(pdbgen PRIVATE "include")

llvm_map_components_to_libnames(llvm_libs core support DebugInfoPDB)
target_link_libraries(pdbgen ${llvm_libs})