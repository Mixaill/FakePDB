#pragma once

#include <cstdint>
#include <iomanip>
#include <string>
#include <sstream>
#include <vector>

namespace FakePDB::Common {
    struct GUID {
        unsigned long Data1;
        unsigned short Data2;
        unsigned short Data3;
        unsigned char Data4[8];

        [[nodiscard]] std::string ToHex() const {
            std::ostringstream oss;
            oss << std::hex << std::uppercase;

            oss << std::setw(2) << std::setfill('0') << Data1;
            oss << std::setw(2) << std::setfill('0') << Data2;
            oss << std::setw(2) << std::setfill('0') << Data3;
            for (auto i : Data4) {
                oss << std::setw(2) << std::setfill('0') << (unsigned) i;
            }

            return oss.str();
        }

        static std::string ToHex(const std::vector<uint8_t> &vec) {
            auto *guid = reinterpret_cast<const GUID *>(vec.data());
            return guid->ToHex();
        }
    };
}
