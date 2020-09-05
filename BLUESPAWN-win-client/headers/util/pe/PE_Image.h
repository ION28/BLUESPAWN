#ifndef PE_IMAGE_H
#define PE_IMAGE_H

#include <Windows.h>
#include <winternl.h>

#include <map>
#include <optional>

#include "util/Wrappers.hpp"

#include "util/pe/PE_Section.h"
#include "Relocation_Section.h"
#include "Import_Section.h"
#include "Export_Section.h"
#include "Resource_Section.h"

enum Architecture { x86, x64 };

class PE_Image {
private:
	DWORD dwHeaderSize;
	MemoryWrapper<> BaseAddress;

public:
	MemoryWrapper<> base;
	std::optional<std::wstring> swzImageName;
	std::optional<std::wstring> swzImagePath;

	Architecture arch;

	bool expanded;
	bool freeOnDestroy;

	std::map<std::string, PE_Section> sections;

	Relocation_Section* relocations;
	Import_Section* imports;
	Export_Section* exports;
	Resource_Section* resources;

	DWORD dwExpandSize;
	DWORD dwImageSize;
	DWORD dwEntryPoint;

	PE_Image(LPVOID lpBaseAddress, HANDLE hProcess = GetCurrentProcess(), bool expanded = false, 
		std::optional<std::wstring> swzImageName = std::nullopt, std::optional<std::wstring> swzImagePath = std::nullopt);
	PE_Image(std::wstring FileName);
	~PE_Image();

	bool ValidatePE() const;

	DWORD RVAToOffset(DWORD rva) const;
	DWORD OffsetToRVA(DWORD rva) const;

	std::optional<PE_Image> LoadTo(MemoryWrapper<> target, bool AvoidTargetChanges = false);

	bool ApplyLocalRelocations(DWORD64 offset);
	bool ApplyTargetRelocations(MemoryWrapper<> target) const;

	bool ParseLocalImports(HandleWrapper process);
	bool ParseTargetImports(MemoryWrapper<> target) const;

	bool ApplyProtections(MemoryWrapper<> target) const;
};

#endif
