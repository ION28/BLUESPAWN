#pragma once
#include "util/pe/PE_Section.h"

#include <string>
#include <vector>

#include "util/DynamicLinker.h"

DEFINE_FUNCTION(NTSTATUS, LdrpPreprocessDllName, NTAPI, __in PUNICODE_STRING input, __out PUNICODE_STRING output, PULONG_PTR zero1, PULONG_PTR zero2);

struct PE_Export {
	DWORD rva;
	WORD ordinal;
	std::string name;
	std::wstring redirect;

	PE_Export(DWORD rva, WORD ordinal, std::string name);
	PE_Export(WORD ordinal, std::string name, std::wstring redirect);
};

class Export_Section : public PE_Section {
public:
	std::vector<PE_Export> exports;
	IMAGE_EXPORT_DIRECTORY ExportDirectory;

	Export_Section(const PE_Section& section);

	DWORD64 GetExportAddress(std::string name) const;
	DWORD64 GetExportAddress(WORD ordinal) const;
};

