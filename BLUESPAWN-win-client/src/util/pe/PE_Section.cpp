#include "util/pe/PE_Section.h"
#include "util/pe/PE_Image.h"

#include <Windows.h>

#include <string>

PE_Section::PE_Section(const PE_Image& image, IMAGE_SECTION_HEADER SectionHeader, MemoryWrapper<> lpImageBase, bool expanded) : 
	AssociatedImage{ image },
	expanded{ expanded },
	SectionContent{ lpImageBase.GetOffset(expanded ? SectionHeader.VirtualAddress : SectionHeader.PointerToRawData) }{
	this->SectionHeader = SectionHeader;

	WCHAR signature[9]{};
	for(int i = 0; i < 8; i++){
		signature[i] = SectionHeader.Name[i];
	}

	this->Signature = signature;
}

PE_Section::PE_Section(const PE_Section& copy) :
	SectionHeader{ detection->SectionHeader },
	SectionContent{ detection->SectionContent },
	Signature{ detection->Signature },
	AssociatedImage{ detection->AssociatedImage },
	expanded{ detection->expanded }{}

bool PE_Section::ContainsOffset(DWORD offset) const {
	return offset >= SectionHeader.PointerToRawData && offset < SectionHeader.PointerToRawData + SectionHeader.SizeOfRawData;
}

bool PE_Section::ContainsRVA(DWORD rva) const {
	return rva >= SectionHeader.VirtualAddress && rva < SectionHeader.VirtualAddress + SectionHeader.SizeOfRawData;
}

DWORD PE_Section::ConvertOffsetToRVA(DWORD offset) const {
	return ContainsOffset(offset) ? offset - SectionHeader.PointerToRawData + SectionHeader.VirtualAddress : 0;
}

DWORD PE_Section::ConvertRVAToOffset(DWORD offset) const {
	return ContainsRVA(offset) ? offset - SectionHeader.VirtualAddress + SectionHeader.SizeOfRawData : 0;
}

std::wstring PE_Section::GetSignature() const {
	return Signature;
}

PE_Section::operator IMAGE_SECTION_HEADER() const {
	return SectionHeader;
}