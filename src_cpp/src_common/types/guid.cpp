#include "types/guid.h"

std::string FakePDB::Common::GUID::ToHex() const {
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

std::string FakePDB::Common::GUID::ToHex(const std::vector<uint8_t> &vec) {
    auto *guid = reinterpret_cast<const GUID *>(vec.data());
    return guid->ToHex();
}

std::string FakePDB::Common::GUID::ToHex(const llvm::codeview::GUID& vec) {
    auto* guid = reinterpret_cast<const GUID*>(vec.Guid);
    return guid->ToHex();
}
