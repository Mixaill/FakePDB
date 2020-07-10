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

if (MSVC)
    # silence warnings from LLVM headers
    add_compile_options(/experimental:external /external:anglebrackets /external:W0)
    add_compile_definitions(_SILENCE_CXX17_ITERATOR_BASE_CLASS_DEPRECATION_WARNING)

    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra)
endif()

add_library(pdbgen_common STATIC)
target_sources(pdbgen_common PRIVATE
    guidhelper.h
    hexhelper.h

    pefile.cpp
    pefile.h

    idadb.cpp
    idadb.h

    pdbcreator.cpp
    pdbcreator.h
)
target_include_directories(pdbgen_common PUBLIC ${LLVM_INCLUDE_DIRS})
target_include_directories(pdbgen_common PUBLIC "include")
target_include_directories(pdbgen_common PUBLIC ".")

llvm_map_components_to_libnames(llvm_libs core support DebugInfoPDB)
target_link_libraries(pdbgen_common ${llvm_libs})

add_executable(pdbgen)
target_sources(pdbgen PRIVATE main.cpp)
target_link_libraries(pdbgen PRIVATE pdbgen_common)

add_executable(pdbgen_test_pefile_1)
target_sources(pdbgen_test_pefile_1 PRIVATE "test/test_pefile_1.cpp")
target_link_libraries(pdbgen_test_pefile_1 PRIVATE pdbgen_common)

install(
    TARGETS pdbgen
    RUNTIME DESTINATION bin
)