#include "util/pe/PE_Image.h"
#include "util/pe/PE_Section.h"
#include "util/wrappers.hpp"

bool PE_Image::ValidatePE() const {
	MemoryWrapper<> PESignature = { new BYTE[2]{0x4D, 0x5A}, 2 };
	MemoryWrapper<> PE2Signature = { new BYTE[4]{0x50, 0x45, 0x00, 0x00}, 4 };
	return base.CompareMemory(PESignature) && base.GetOffset(base.Convert<IMAGE_DOS_HEADER>()->e_lfanew).CompareMemory(PE2Signature);
}

IMAGE_SECTION_HEADER CreateVirtualHeader(std::string name, DWORD dwRVA, DWORD dwSize, DWORD dwRawAddress){
	IMAGE_SECTION_HEADER VirtualHeader = { 0, 0, 0, 0, 0, 0, 0, 0, dwSize, dwRVA, dwSize, dwRawAddress, 0, 0, 0, 0, IMAGE_SCN_MEM_READ };
	for(int idx = 0; idx < name.length(); idx++){
		VirtualHeader.Name[idx] = static_cast<BYTE>(name.at(idx));
	}
	return VirtualHeader;
}

PE_Image::PE_Image(LPVOID lpBaseAddress, HANDLE hProcess, bool expanded, std::optional<std::wstring> swzImageName,
	std::optional<std::wstring> swzImagePath) : 
	expanded{ expanded },
	base{ nullptr },
	BaseAddress{ nullptr },
	relocations{ nullptr },
	imports{ nullptr },
	exports{ nullptr },
	resources{ nullptr },
	swzImageName{ swzImageName },
	swzImagePath{ swzImagePath }{
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
	this->dwEntryPoint = arch == x64 ? NTHeaders64.OptionalHeader.AddressOfEntryPoint : NTHeaders32.OptionalHeader.AddressOfEntryPoint;

	this->sections = {};
	MemoryWrapper<IMAGE_SECTION_HEADER> SectionHeaders = {
		NTHeaderStart.GetOffset(arch == x64 ? sizeof(NTHeaders64) : sizeof(NTHeaders32)),
		(arch == x64 ? NTHeaders64.FileHeader.NumberOfSections : NTHeaders32.FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER),
		hProcess
	};

	do sections.emplace(PCHAR(SectionHeaders->Name), PE_Section{ *this, *SectionHeaders, MemoryWrapper<>{ lpBaseAddress, 0xFFFFFFFF, hProcess}, expanded });
	while(SectionHeaders = SectionHeaders.GetOffset(sizeof(IMAGE_SECTION_HEADER)));

	for(auto entry : sections){
		IMAGE_SECTION_HEADER header = entry.second;
		this->dwImageSize = max(dwImageSize, header.PointerToRawData + header.SizeOfRawData);
	}

	this->base = { lpBaseAddress, expanded ? dwExpandSize : dwImageSize, hProcess };

	DWORD dwExportSize = arch == x64 ? NTHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size :
		NTHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	DWORD dwExportRVA = arch == x64 ? NTHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress :
		NTHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	this->exports = new Export_Section(PE_Section(*this, CreateVirtualHeader(".edata", dwExportRVA, dwExportSize, RVAToOffset(dwExportRVA)), base, expanded));

	DWORD dwImportSize = arch == x64 ? NTHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size :
		NTHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	DWORD dwImportRVA = arch == x64 ? NTHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress :
		NTHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	this->imports = new Import_Section(PE_Section(*this, CreateVirtualHeader(".idata", dwImportRVA, dwImportSize, RVAToOffset(dwImportRVA)), base, expanded));

	DWORD dwRelocSize = arch == x64 ? NTHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size :
		NTHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	DWORD dwRelocRVA = arch == x64 ? NTHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress :
		NTHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	this->relocations = new Relocation_Section(PE_Section(*this, CreateVirtualHeader(".reloc", dwRelocRVA, dwRelocSize, RVAToOffset(dwRelocRVA)), base, expanded));

	DWORD dwResourceSize = arch == x64 ? NTHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size :
		NTHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
	DWORD dwResourceRVA = arch == x64 ? NTHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress :
		NTHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
	this->resources = new Resource_Section(PE_Section(*this, CreateVirtualHeader(".rsrc", dwResourceRVA, dwResourceSize, RVAToOffset(dwResourceRVA)), base, expanded));
}

std::optional<PE_Image> PE_Image::LoadTo(MemoryWrapper<> location, bool AvoidTargetChanges){
	if(location.MemorySize < dwExpandSize || !ValidatePE()){
		return std::nullopt;
	} else {
		if(AvoidTargetChanges){
			if(!ApplyLocalRelocations(reinterpret_cast<DWORD64>(location.address) - BaseAddress)) return std::nullopt;
			if(!ParseLocalImports(location.process)) return std::nullopt;
			if(!location.Write(base, dwHeaderSize, 0)) return std::nullopt;

			for(auto section : sections){
				if(!location.Write(section.second.SectionContent, section.second.SectionContent.MemorySize, 0)) return std::nullopt;
			}
		} else {
			if(!location.Write(base, dwHeaderSize, 0)) return std::nullopt;

			for(auto section : sections){
				if(!location.Write(section.second.SectionContent, section.second.SectionContent.MemorySize, 0)) return std::nullopt;
			}

			if(!ApplyTargetRelocations(location)) return std::nullopt;
			if(!ParseTargetImports(location)) return std::nullopt;
		}

		if(!ApplyProtections(location)) return std::nullopt;

		return std::optional<PE_Image>{PE_Image{ location.address, location.process, true }};
	}
}

bool PE_Image::ApplyLocalRelocations(DWORD64 offset){
	if(!ValidatePE() || relocations->GetSignature() != L".reloc"){
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

	auto RelocRVAs = relocations->GetRelocRVAs();

	for(auto rva : RelocRVAs){
		rva = relocations->ConvertRVAToOffset(rva);

		DWORD64 PatchedMemory64 = offset + *base.GetOffset(rva).Convert<DWORD64>();
		DWORD PatchedMemory32 = static_cast<DWORD>(offset + *base.GetOffset(rva).Convert<DWORD>());
		if(!base.Write(arch == x64 ? (PCHAR) &PatchedMemory64 : (PCHAR) &PatchedMemory32, arch == x64 ? 8 : 4, rva)){
			return false;
		}
	}

	return true;
}

bool PE_Image::ApplyTargetRelocations(MemoryWrapper<> TargetLocation) const {
	DWORD64 offset = reinterpret_cast<DWORD64>(TargetLocation.address) - BaseAddress;

	if(relocations->GetSignature() != L".reloc"){
		return false;
	}

	auto RelocRVAs = relocations->GetRelocRVAs();

	DWORD BaseOffset = static_cast<DWORD>(reinterpret_cast<DWORD64>(BaseAddress.address) - reinterpret_cast<DWORD64>(base.address));
	if(arch == x64) {
		TargetLocation.Convert<DWORD64>().Write(&offset, 8, BaseOffset);
	} else {
		DWORD off32 = static_cast<DWORD>(offset);
		TargetLocation.Convert<DWORD>().Write(&off32, 4, BaseOffset);
	}

	for(auto rva : RelocRVAs){
		DWORD64 PatchedMemory64 = offset + *base.GetOffset(rva).Convert<DWORD64>();
		DWORD PatchedMemory32 = static_cast<DWORD>(offset + *base.GetOffset(rva).Convert<DWORD>());
		if(!TargetLocation.Write(arch == x64 ? (PCHAR) &PatchedMemory64 : (PCHAR) &PatchedMemory32, arch == x64 ? 8 : 4, rva)){
			return false;
		}
	}

	return true;
}

bool PE_Image::ParseLocalImports(HandleWrapper process){
	return imports->LoadAllImports(process);
}

bool PE_Image::ParseTargetImports(MemoryWrapper<> TargetLocation) const {
	return imports->LoadAllImports(TargetLocation.process);
}

bool PE_Image::ApplyProtections(MemoryWrapper<> TargetLocation) const {
	TargetLocation.Protect(PAGE_READONLY);

	DWORD dwProtectionMap[8]{
		PAGE_NOACCESS,           PAGE_READONLY,
		PAGE_READWRITE,          PAGE_READWRITE,

		PAGE_EXECUTE,            PAGE_EXECUTE_READ,
		PAGE_EXECUTE_WRITECOPY,  PAGE_EXECUTE_READWRITE,
	};

	for(auto pair : sections){
		DWORD dwProtIdx = ((pair.second.SectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) ? 4 : 0) +
			((pair.second.SectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE) ? 2 : 0) +
			((pair.second.SectionHeader.Characteristics & IMAGE_SCN_MEM_READ) ? 1 : 0);
		DWORD protection = dwProtectionMap[dwProtIdx];
		protection |= (pair.second.SectionHeader.Characteristics & IMAGE_SCN_MEM_NOT_CACHED) ? PAGE_NOACCESS : 0;
		if(!TargetLocation.GetOffset(pair.second.SectionHeader.VirtualAddress).Protect(protection, pair.second.SectionHeader.SizeOfRawData)){
			return false;
		}
	}
	return true;
}

DWORD PE_Image::RVAToOffset(DWORD rva) const {
	for(auto pair : sections){
		if(pair.second.ContainsRVA(rva)){
			return pair.second.ConvertRVAToOffset(rva);
		}
	}

	return rva;
}

DWORD PE_Image::OffsetToRVA(DWORD offset) const {
	for(auto pair : sections){
		if(pair.second.ContainsOffset(offset)){
			return pair.second.ConvertOffsetToRVA(offset);
		}
	}

	return offset;
}