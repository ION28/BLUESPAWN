#pragma once

#include <Windows.h>

#include <string>

#include "Common/Wrappers.hpp"

class PE_Image;
class PE_Section {
public:
	MemoryWrapper<> SectionContent;
	const PE_Image& AssociatedImage;

	IMAGE_SECTION_HEADER SectionHeader;

	std::wstring Signature;

	bool expanded;

	PE_Section(const PE_Image& image, PIMAGE_SECTION_HEADER SectionHeader = nullptr, MemoryWrapper<> lpImageBase = { nullptr }, bool expanded = false);
	PE_Section(const PE_Section& copy);

	bool ContainsRVA(DWORD rva);
	bool ContainsOffset(DWORD offset);

	DWORD ConvertOffsetToRVA(DWORD offset);
	DWORD ConvertRVAToOffset(DWORD rva);

	std::wstring GetSignature();

	operator IMAGE_SECTION_HEADER();
};

