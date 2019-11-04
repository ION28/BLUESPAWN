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

	bool ContainsRVA(DWORD rva) const;
	bool ContainsOffset(DWORD offset) const;

	DWORD ConvertOffsetToRVA(DWORD offset) const;
	DWORD ConvertRVAToOffset(DWORD rva) const;

	std::wstring GetSignature() const;

	operator IMAGE_SECTION_HEADER() const;
};

