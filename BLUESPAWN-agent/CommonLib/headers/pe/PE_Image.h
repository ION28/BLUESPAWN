#ifndef PE_IMAGE_H
#define PE_IMAGE_H

#include <Windows.h>
#include <winternl.h>

#include <map>

#include "common/Wrappers.hpp"

#include "PE_Section.h"
#include "Relocation_Section.h"
#include "Import_Section.h"
#include "Export_Section.h"
#include "Resource_Section.h"

enum Architecture { x86, x64 };

class PE_Image {
private:
	DWORD64 BaseAddress;
	DWORD dwHeaderSize;
	MemoryWrapper<> BaseAddress{ nullptr };

public:
	MemoryWrapper<> base{ nullptr };

	Architecture arch;

	bool expanded;

	std::map<std::string, PE_Section> sections;

	Relocation_Section* relocations{ nullptr };
	Import_Section* imports{ nullptr };
	Export_Section* exports{ nullptr };
	Resource_Section* resources{ nullptr };

	DWORD dwExpandSize;
	DWORD dwImageSize;

	PE_Image(LPVOID lpBaseAddress, HANDLE hProcess = GetCurrentProcess(), bool expanded = false);

	bool ValidatePE();

	DWORD RVAToOffset(DWORD rva);
	DWORD OffsetToRVA(DWORD rva);

	PE_Image LoadTo(MemoryWrapper<> target, bool AvoidTargetChanges = false);

	bool ApplyLocalRelocations(DWORD64 offset);
	bool ApplyTargetRelocations(MemoryWrapper<> target);

	bool ParseLocalImports(HandleWrapper process);
	bool ParseTargetImports(MemoryWrapper<> target);

	bool ApplyProtections(MemoryWrapper<> target);
};

#endif
