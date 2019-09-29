#pragma once
#include "PE_Section.h"

#include <string>
#include <vector>

struct PE_Export {
	DWORD rva;
	WORD ordinal;
	std::string name;
	std::string redirect;

	PE_Export(DWORD rva, WORD ordinal, std::string name);
};

class Export_Section : public PE_Section {
public:
	std::vector<PE_Export> exports;
	IMAGE_EXPORT_DIRECTORY ExportDirectory;

	Export_Section(const PE_Section& section);

	LPVOID GetExportAddress(std::string name);
	LPVOID GetExportAddress(WORD ordinal);
};

