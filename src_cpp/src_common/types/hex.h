#pragma once

#include <iomanip>
#include <string>
#include <sstream>

namespace FakePDB::Common {
    class Hex {
    public:
        Hex() = delete;
        ~Hex() = delete;

        template<typename T>
        static std::string IntToHex(T i) {
            std::ostringstream oss;
            oss << std::hex << std::uppercase << i;
            return oss.str();
        }
    };
}
