#pragma once

#include <Windows.h>

#include <string>

#include "Common/Wrappers.hpp"

class PE_Section {
public:
	MemoryWrapper<> SectionContent;

	IMAGE_SECTION_HEADER SectionHeader;

	std::wstring Signature;

	PE_Section(PIMAGE_SECTION_HEADER SectionHeader, MemoryWrapper<> lpImageBase, bool expanded);
	PE_Section(const PE_Section& copy);

	bool ContainsRVA(DWORD rva);
	bool ContainsOffset(DWORD offset);

	DWORD ConvertOffsetToRVA(DWORD offset);
	DWORD ConvertRVAToOffset(DWORD rva);

	std::wstring GetSignature();

	operator IMAGE_SECTION_HEADER();
};

