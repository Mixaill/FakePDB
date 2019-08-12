#pragma once

#include <iomanip>
#include <string>
#include <sstream>

template< typename T >
std::string intToHex(T i)
{
	std::ostringstream oss;
	oss << std::hex << std::uppercase << i;
	return oss.str();
}