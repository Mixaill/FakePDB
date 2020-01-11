#include <iostream>

#include "pefile.h"

void peinfo(const std::filesystem::path& path) {
	PeFile pefile(path);
	std::cout << "ImageSize   : " << pefile.GetImageSize()   << std::endl;
	std::cout << "PdbAge      : " << pefile.GetPdbAge()      << std::endl;
	std::cout << "PdbFilepath : " << pefile.GetPdbFilepath() << std::endl;
	std::cout << "PdbFilename : " << pefile.GetPdbFilename() << std::endl;
	std::cout << "Timestamp   : " << pefile.GetTimestamp()   << std::endl;
	std::cout << "Machine     : " << pefile.GetMachine()     << std::endl;


	for (const auto& header : pefile.GetSectionHeaders()) {
		std::cout << "Header      : " << std::endl;
		std::cout << "    - Name  : " << header.Name << std::endl;
		std::cout << "    - VA    : " << std::hex << header.VirtualAddress << std::endl;
		std::cout << "    - VS    : " << std::hex << header.VirtualSize << std::endl;

	}

	std::cout << std::endl;
}

int main() {
	peinfo(std::filesystem::path("test_1_32.exe"));
	peinfo(std::filesystem::path("test_1_64.exe"));
	
	return 0;
}