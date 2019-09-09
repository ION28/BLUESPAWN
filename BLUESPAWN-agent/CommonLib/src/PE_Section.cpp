#include "pe/PE_Section.h"

#include <Windows.h>

#include <string>

PE_Section::PE_Section(PIMAGE_SECTION_HEADER SectionHeader, MemoryWrapper<> lpImageBase, bool expanded)
	: SectionContent{ lpImageBase.GetOffset(expanded ? SectionHeader->VirtualAddress : SectionHeader->PointerToRawData) }{
	this->SectionHeader = *SectionHeader;

	WCHAR signature[9]{};
	for(int i = 0; i < 8; i++){
		signature[i] = SectionHeader->Name[i];
	}

	this->Signature = signature;
}

PE_Section::PE_Section(const PE_Section& copy) :
	SectionHeader{ copy.SectionHeader },
	SectionContent{ copy.SectionContent },
	Signature{ copy.Signature }{}

bool PE_Section::ContainsOffset(DWORD offset){
	return offset >= SectionHeader.PointerToRawData && offset < SectionHeader.PointerToRawData + SectionHeader.SizeOfRawData;
}

bool PE_Section::ContainsRVA(DWORD rva){
	return rva >= SectionHeader.VirtualAddress && rva < SectionHeader.VirtualAddress + SectionHeader.SizeOfRawData;
}

DWORD PE_Section::ConvertOffsetToRVA(DWORD offset){
	return ContainsOffset(offset) ? offset - SectionHeader.PointerToRawData + SectionHeader.VirtualAddress : 0;
}

DWORD PE_Section::ConvertRVAToOffset(DWORD offset){
	return ContainsRVA(offset) ? offset - SectionHeader.VirtualAddress + SectionHeader.SizeOfRawData : 0;
}

std::wstring PE_Section::GetSignature(){
	return Signature;
}

PE_Section::operator IMAGE_SECTION_HEADER(){
	return SectionHeader;
}