#pragma once

//stdlib
#include <filesystem>
#include <vector>

//fakepdb
#include "root.h"

namespace FakePDB::Data{
    class DB {
    public:
        explicit DB();
        explicit DB(std::filesystem::path& filepath);

        SectionGeneral& General();
        SectionPE& PE();
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