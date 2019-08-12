#
#   Copyright 2019 Mikhail Paulyshka
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

cmake_minimum_required(VERSION 3.4.3)
project(PDBGenLLVM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(LLVM REQUIRED CONFIG)

include_directories(${LLVM_INCLUDE_DIRS})

set(PDBGEN_SOURCES

	guidhelper.h
	hexhelper.h

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