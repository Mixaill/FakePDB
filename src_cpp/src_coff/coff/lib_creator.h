#pragma once

//stdlib
#include <filesystem>

//fakepdb
#include "data/db.h"

namespace FakePDB::COFF {
    class LibCreator {
    public:
        LibCreator() = delete;
        ~LibCreator() = delete;

        static bool Create(Data::DB &db, std::filesystem::path& path);
    };
}
