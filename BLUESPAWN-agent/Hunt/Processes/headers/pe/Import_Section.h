#pragma once
#include "PE_Section.h"

#include <vector>
#include <string>
#include <set>

class Import_Library {
public:
	std::wstring sLibraryName;
	std::wstring sLibraryPath;

	std::vector<std::wstring> vImportedFunctions;
	std::vector<DWORD> vFunctionRVAs;
	std::vector<DWORD> vIATFuncAddrRVA;

	std::vector<std::wstring> vImports;

	std::set<std::wstring> GetRequiredLibraries();

	bool LoadImportLibrary(MemoryWrapper<> BaseAddress, HANDLE ProcessScope, bool Expanded);
};

class Import_Section : public PE_Section {
public:
	std::vector<Import_Library> imports;

	bool LoadAllImports(MemoryWrapper<> BaseAddress, HANDLE ProcessScope, bool Expanded);

	Import_Section(const PE_Section& section);
};

