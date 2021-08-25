#
#   Copyright 2019-2021 Mikhail Paulyshka
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

#
# Global project settings
#

cmake_minimum_required(VERSION 3.16)
project(FakePDB)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

#
# Packages
#
find_package(LLVM REQUIRED CONFIG)

#
# Compiler settings
#

if (MSVC)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    add_compile_definitions(_SILENCE_CXX17_ITERATOR_BASE_CLASS_DEPRECATION_WARNING)
    add_compile_definitions(__STDC_WANT_SECURE_LIB__=1)

    add_compile_options(/Wall)
    add_compile_options(/wd4061 /wd4100 /wd4146 /wd4242 /wd4244 /wd4245 /wd4266 /wd4267 /wd4324 /wd4365 /wd4458 /wd4459 /wd4514 /wd4582 /wd4583 /wd4623 /wd4624 /wd4625 /wd4626 /wd4702 /wd4710 /wd4711 /wd4774 /wd4800 /wd4820 /wd5026 /wd5027 /wd5045)
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-Wall -Wextra -Wno-unused-parameter)
endif()



#
# LLVM
#
llvm_map_components_to_libnames(llvm_libs core support DebugInfoPDB)

#
# fakepdb_common
#

add_library(fakepdb_common STATIC)

target_sources(fakepdb_common PRIVATE
        src_common/commands/command_executor.cpp
        src_common/commands/command_executor.h
        src_common/commands/command_interface.h

        src_common/data/db.cpp
        src_common/data/db.h
        src_common/data/export.h
        src_common/data/function.h
        src_common/data/general.h
        src_common/data/label.h
        src_common/data/name.h
        src_common/data/pe.h
        src_common/data/root.h
        src_common/data/segment.cpp
        src_common/data/segment.h

        src_common/nlohmann/json.hpp

        src_common/types/guid.cpp
        src_common/types/guid.h
        src_common/types/hex.h
)

target_compile_definitions(fakepdb_common PUBLIC JSON_DIAGNOSTICS=1)

target_include_directories(fakepdb_common PUBLIC src_common)
target_include_directories(fakepdb_common PUBLIC ${LLVM_INCLUDE_DIRS})

target_link_libraries(fakepdb_common PUBLIC ${llvm_libs})



#
# fakepdb_coff
#

add_executable(fakepdb_coff)

target_sources(fakepdb_coff PRIVATE
        src_coff/coff/lib_creator.cpp
        src_coff/coff/lib_creator.h
        src_coff/commands/command_coff_createlib.h

        src_coff/main.cpp
        )

target_include_directories(fakepdb_coff PRIVATE src_coff)
target_link_libraries(fakepdb_coff PRIVATE fakepdb_common)

install(
        TARGETS fakepdb_coff
        RUNTIME DESTINATION bin
)



#
# fakepdb_pdb
#

add_executable(fakepdb_pdb)

target_sources(fakepdb_pdb PRIVATE
        src_pdb/commands/command_pdb_generate.h

        src_pdb/pdb/pdb_creator.cpp
        src_pdb/pdb/pdb_creator.h
        src_pdb/pdb/pdb_symfactory.cpp
        src_pdb/pdb/pdb_symfactory.h

        src_pdb/main.cpp
)

target_include_directories(fakepdb_pdb PRIVATE src_pdb)
target_link_libraries(fakepdb_pdb PRIVATE fakepdb_common)

install(
        TARGETS fakepdb_pdb
        RUNTIME DESTINATION bin
)



#
# fakepdb_pe
#

add_executable(fakepdb_pe)

target_sources(fakepdb_pe PRIVATE
        src_pe/commands/command_pe_exports.h
        src_pe/commands/command_pe_guidage.h
        src_pe/commands/command_pe_timestamp.h

        src_pe/pe/pe_file.cpp
        src_pe/pe/pe_file.h

        src_pe/main.cpp
        )

target_include_directories(fakepdb_pe PRIVATE src_pe)
target_link_libraries(fakepdb_pe PRIVATE fakepdb_common)

install(
    TARGETS fakepdb_pe
    RUNTIME DESTINATION bin
)
