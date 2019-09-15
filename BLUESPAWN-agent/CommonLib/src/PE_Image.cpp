#include "pe/PE_Image.h"
#include "pe/PE_Section.h"
#include "common/wrappers.hpp"

bool PE_Image::ValidatePE(){
	MemoryWrapper<> PESignature = { new BYTE[2]{0x4D, 0x5A}, 2 };
	MemoryWrapper<> PE2Signature = { new BYTE[4]{0x50, 0x45, 0x00, 0x00}, 4 };
	return base.CompareMemory(PESignature) && base.GetOffset(base.Convert<IMAGE_DOS_HEADER>()->e_lfanew).CompareMemory(PE2Signature);
}

PE_Image::PE_Image(LPVOID lpBaseAddress, HANDLE hProcess, bool expanded) : expanded{ expanded } {

	MemoryWrapper<IMAGE_DOS_HEADER> dos = { lpBaseAddress, sizeof(IMAGE_DOS_HEADER), hProcess };

	DWORD NTHeaderOffset = dos->e_lfanew;

	MemoryWrapper<WORD> NTHeaderStart = { lpBaseAddress, NTHeaderOffset + 3 * sizeof(WORD), hProcess };
	WORD architecture = *NTHeaderStart.GetOffset(NTHeaderOffset).GetOffset(2 * sizeof(WORD));
	arch = architecture == IMAGE_FILE_MACHINE_I386 ? x86 : x64;

	auto NTHeaders32 = *MemoryWrapper<IMAGE_NT_HEADERS32>{ NTHeaderStart, sizeof(IMAGE_NT_HEADERS32), hProcess };
	auto NTHeaders64 = *MemoryWrapper<IMAGE_NT_HEADERS64>{ NTHeaderStart, sizeof(IMAGE_NT_HEADERS64), hProcess };

	this->BaseAddress = arch == 64 ? MemoryWrapper<>{&(NTHeaderStart.Convert<IMAGE_NT_HEADERS64>()->OptionalHeader.ImageBase), 8, hProcess} :
		MemoryWrapper<>{ &(NTHeaderStart.Convert<IMAGE_NT_HEADERS32>()->OptionalHeader.ImageBase), 4, hProcess };

	this->dwExpandSize = arch == x64 ? NTHeaders64.OptionalHeader.SizeOfImage : NTHeaders32.OptionalHeader.SizeOfImage;
	this->dwHeaderSize = arch == x64 ? NTHeaders64.OptionalHeader.SizeOfHeaders : NTHeaders32.OptionalHeader.SizeOfHeaders;

	this->sections = {};
	MemoryWrapper<IMAGE_SECTION_HEADER> SectionHeaders = {
		NTHeaderStart.GetOffset(arch == x64 ? sizeof(NTHeaders64) : sizeof(NTHeaders32)),
		(arch == x64 ? NTHeaders64.FileHeader.NumberOfSections : NTHeaders32.FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER),
		hProcess
	};

	do sections.emplace(SectionHeaders->Name, PE_Section{ SectionHeaders, MemoryWrapper<>{ lpBaseAddress, 0xFFFFFFFF, hProcess}, expanded });
	while(SectionHeaders = SectionHeaders.GetOffset(sizeof(IMAGE_SECTION_HEADER)));

	this->resources = sections.find(".rsrc") == sections.end() ? PE_Section{nullptr, nullptr, false} : sections[".rsrc"];
	this->relocations = sections.find(".reloc") == sections.end() ? PE_Section{ nullptr, nullptr, false } : sections[".reloc"];
	this->imports = sections.find(".idata") == sections.end() ? PE_Section{ nullptr, nullptr, false } : sections[".idata"];
	this->exports = sections.find(".edata") == sections.end() ? PE_Section{ nullptr, nullptr, false } : sections[".edata"];

	for(auto entry : sections){
		IMAGE_SECTION_HEADER header = entry.second;
		this->dwImageSize = max(dwImageSize, header.PointerToRawData + header.SizeOfRawData);
	}

	this->base = { lpBaseAddress, expanded ? dwExpandSize : dwImageSize, hProcess };
}

PE_Image PE_Image::LoadTo(MemoryWrapper<> location, bool AvoidTargetChanges){
	if(location.MemorySize < dwExpandSize){
		return nullptr;
	} else {
		if(AvoidTargetChanges){
			ApplyLocalRelocations(reinterpret_cast<DWORD64>(location.address) - BaseAddress);
			ParseLocalImports(location.process);
			location.Write(base, dwHeaderSize, 0);

			for(auto section : sections){
				location.Write(section.second.SectionContent, section.second.SectionContent.MemorySize, 0);
			}
		} else {
			location.Write(base, dwHeaderSize, 0);

			for(auto section : sections){
				location.Write(section.second.SectionContent, section.second.SectionContent.MemorySize, 0);
			}

			ApplyTargetRelocations(location);
			ParseTargetImports(location);
		}

		ApplyProtections(location);

		return { location.address, location.process, true };
	}
}

bool PE_Image::ApplyLocalRelocations(DWORD64 offset){
	if(relocations.GetSignature() != L".reloc"){
		return false;
	}

	if(expanded){
		return ApplyTargetRelocations(base);
	}

	if(arch == x64) {
		BaseAddress.Convert<DWORD64>().Write(&offset);
	} else {
		DWORD off32 = static_cast<DWORD>(offset);
		BaseAddress.Convert<DWORD>().Write(&off32);
	}

	auto RelocRVAs = relocations.GetRelocRVAs();

	for(auto rva : RelocRVAs){
		rva = relocations.ConvertRVAToOffset(rva);

		DWORD64 PatchedMemory64 = offset + *base.GetOffset(rva).Convert<DWORD64>();
		DWORD PatchedMemory32 = offset + *base.GetOffset(rva).Convert<DWORD>();
		if(!base.Write(arch == x64 ? (LPVOID) & PatchedMemory64 : (LPVOID) & PatchedMemory32, arch == x64 ? 8 : 4, rva)){
			return false;
		}
	}

	return true;
}

bool PE_Image::ApplyTargetRelocations(MemoryWrapper<> TargetLocation){
	DWORD64 offset = reinterpret_cast<DWORD64>(TargetLocation.address) - BaseAddress;

	if(relocations.GetSignature() != L".reloc"){
		return false;
	}

	auto RelocRVAs = relocations.GetRelocRVAs();

	DWORD BaseOffset = reinterpret_cast<DWORD>(BaseAddress.address) - reinterpret_cast<DWORD>(base.address);
	if(arch == x64) {
		TargetLocation.Convert<DWORD64>().Write(&offset, 8, BaseOffset);
	} else {
		DWORD off32 = static_cast<DWORD>(offset);
		TargetLocation.Convert<DWORD>().Write(&off32, 4, BaseOffset);
	}

	for(auto rva : RelocRVAs){
		DWORD64 PatchedMemory64 = offset + *base.GetOffset(rva).Convert<DWORD64>();
		DWORD PatchedMemory32 = offset + *base.GetOffset(rva).Convert<DWORD>();
		if(!TargetLocation.Write(arch == x64 ? (LPVOID) &PatchedMemory64 : (LPVOID) &PatchedMemory32, arch == x64 ? 8 : 4, rva)){
			return false;
		}
	}

	return true;
}

bool PE_Image::ParseLocalImports(HandleWrapper process){
	imports.LoadAllImports(base, process, expanded);
}

bool PE_Image::ParseTargetImports(MemoryWrapper<> TargetLocation){
	imports.LoadAllImports(TargetLocation, TargetLocation.process, true);
}