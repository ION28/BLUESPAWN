#pragma once
#include "util/pe/pe_section.h"

#include <vector>
#include <string>
#include <map>
#include <set>

#pragma pack(push, 1)

typedef struct _IMPORT_DIRECTORY_TABLE {
	DWORD dwImportLookupTableRVA;
	DWORD dwTimestamp;
	DWORD dwForwarderChain;  // Microsoft refuses to document this
	DWORD dwNameRVA;
	DWORD dwImportAddressTableRVA;
} IMPORT_DIRECTORY_TABLE, *PIMAGE_DIRECTORY_TABLE;

typedef struct _IMPORT_LOOKUP_TABLE64 {
	DWORD64 type : 1;
	DWORD64 value : 63; // if type = 1, this is a SHORT representing the ordinal to import. 
						// else this is a DWORD representing the hint/name RVA
} IMPORT_LOOKUP_TABLE64, * PIMPORT_LOOKUP_TABLE64;

typedef struct _IMPORT_LOOKUP_TABLE32 {
	DWORD type : 1;
	DWORD value : 31; // if type = 1, this is a SHORT representing the ordinal to import. 
				      // else this is a DWORD representing the hint/name RVA
} IMPORT_LOOKUP_TABLE32, * PIMPORT_LOOKUP_TABLE32;

struct Hint {
	WORD hint;
	std::string name;
};
struct Import {
	bool IsOrdinal;
	WORD ordinal;
	Hint hint;
};

typedef IMPORT_LOOKUP_TABLE64 IMPORT_ADDRESS_TABLE64, *PIMAGE_ADDRESS_TABLE64;
typedef IMPORT_LOOKUP_TABLE32 IMPORT_ADDRESS_TABLE32, *PIMAGE_ADDRESS_TABLE32;

#pragma pack(pop)

class PE_Image;

class Import_Library {
public:
	std::wstring sLibraryName{};
	const PE_Image& image;
	
	Import_Library(const PE_Image& image, const IMPORT_DIRECTORY_TABLE& ImportDirectoryTable);

	// A mapping from Imports to RVAs of the related Import Address Table entry.
	std::vector<std::pair<Import, DWORD>> vImportToIAT{};

	bool LoadImportLibrary(const HandleWrapper& context);
};

class Import_Section : public PE_Section {
public:
	std::vector<Import_Library> imports;

	Import_Section(const PE_Section& section);

	bool LoadAllImports(const HandleWrapper& context);

	std::set<std::wstring> GetRequiredLibraries() const;
};
