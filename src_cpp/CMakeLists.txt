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
# fakepdb executable
#

add_executable(fakepdb)
target_sources(fakepdb PRIVATE
    src/main.cpp

    include/coff/lib_creator.h
    src/coff/lib_creator.cpp

    include/commands/command_coff_createlib.h
    include/commands/command_interface.h
    include/commands/command_pdb_generate.h
    include/commands/command_pe_exports.h
    include/commands/command_pe_guidage.h
    include/commands/command_pe_timestamp.h

    include/common/guid.h
    include/common/hex.h

    include/data/db.h
    include/data/export.h
    include/data/function.h
    include/data/general.h
    include/data/label.h
    include/data/name.h
    include/data/root.h
    include/data/segment.h
    src/data/db.cpp
    src/data/segment.cpp

    include/pdb/pdb_creator.h
    include/pdb/pdb_symfactory.h
    src/pdb/pdb_creator.cpp
    src/pdb/pdb_symfactory.cpp

    include/pe/pe_file.h
    src/pe/pe_file.cpp
)

target_include_directories(fakepdb PUBLIC ${LLVM_INCLUDE_DIRS})
target_include_directories(fakepdb PUBLIC "include")
target_include_directories(fakepdb PUBLIC ".")

llvm_map_components_to_libnames(llvm_libs core support DebugInfoPDB)
target_link_libraries(fakepdb ${llvm_libs})

install(
    TARGETS fakepdb
    RUNTIME DESTINATION bin
)
