#pragma once

//stdlib
#include <filesystem>
#include <vector>

//fakepdb
#include "data/root.h"

namespace FakePDB::Data{
    class DB {
    public:
        explicit DB();
        explicit DB(std::filesystem::path& filepath);

        SectionGeneral& General();
        SegmentArray& Segments();
        std::vector<Export>& Exports();
        std::vector<Function>& Functions();
        std::vector<Name>& Names();

        void Save(std::filesystem::path& filepath);

    private:
        void load(std::filesystem::path& filepath);

        Root _root{};
    };
}