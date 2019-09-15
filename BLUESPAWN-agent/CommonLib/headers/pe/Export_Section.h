#pragma once
#include "PE_Section.h"

#include <string>
#include <vector>

struct PE_Export {
	DWORD rva;
	WORD ordinal;
	std::wstring name;
};

class Export_Section : public PE_Section {
public:
	std::vector<PE_Export> exports;

	Export_Section(const PE_Section& section);
};

