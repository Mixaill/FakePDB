#pragma once

#include <cstdint>
#include <filesystem>
#include <vector>

struct IdaFunction {
    std::string name;
    uint32_t start_ea;
    bool is_public;
    bool is_autonamed;
};

struct IdaName {
    uint32_t ea;
    std::string name;
    bool is_public;
    bool is_func;
};

class IdaDb {
public:
    explicit IdaDb(std::experimental::filesystem::path& filepath);
    std::vector<IdaFunction>& Functions();
    std::vector<IdaName>& Names();
private:
    void load(std::experimental::filesystem::path& filepath);

    std::vector<IdaFunction> _functions;
    std::vector<IdaName> _names;
};