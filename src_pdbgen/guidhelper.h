#pragma once

#include <cstdint>
#include <iomanip>
#include <string>
#include <sstream>
#include <vector>

static struct GUID {
	unsigned long  Data1;
	unsigned short Data2;
	unsigned short Data3;
	unsigned char  Data4[8];
};

std::string guidToHex(std::vector<uint8_t>& vec)
{
	std::ostringstream oss;
	oss << std::hex << std::uppercase;

	auto* guid = reinterpret_cast<GUID*>(vec.data());
	oss << std::setw(2) << std::setfill('0') << guid->Data1;
	oss << std::setw(2) << std::setfill('0') << guid->Data2;
	oss << std::setw(2) << std::setfill('0') << guid->Data3;
	for (auto i : guid->Data4) {
		oss << std::setw(2) << std::setfill('0') << (unsigned)i;
	}

	return oss.str();
}
