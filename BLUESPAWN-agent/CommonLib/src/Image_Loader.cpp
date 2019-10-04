#include "pe/Image_Loader.h"
#include "logging/Log.h"

#include <functional>

LINK_FUNCTION(NtQueryInformationProcess, NTDLL.dll);

Loaded_Image::Loaded_Image(const LDR_ENTRY& entry, const HandleWrapper& process, bool imported){
	this->EntryPoint = reinterpret_cast<ULONG_PTR>(entry.EntryPoint);
	this->ImageAddress = reinterpret_cast<ULONG_PTR>(entry.DllBase);
	this->ImagePath = MemoryWrapper<WCHAR>{ entry.FullDllName.Buffer, static_cast<SIZE_T>(entry.FullDllName.Length + 1), process }.ReadWstring();
	this->ImageName = MemoryWrapper<WCHAR>{ entry.BaseDllName.Buffer, static_cast<SIZE_T>(entry.BaseDllName.Length + 1), process }.ReadWstring();
	this->ImageSize = entry.SizeOfImage;
	this->ImportsParsed = imported;
}

Image_Loader::Image_Loader(const HandleWrapper& process, LPVOID address) : 
	process{ process }, LoadedImages{}{
	if(!address){
		if(!process && false){
			PROCESS_BASIC_INFORMATION information = {};
			NTSTATUS status = Linker::NtQueryInformationProcess(process, ProcessBasicInformation, &information, sizeof(information), nullptr);
			if(!NT_SUCCESS(status)){
				LOG_ERROR("Error " << status << " occured when finding the PEB of process " << process.Get());
			}

			PEB peb = *MemoryWrapper<PEB>(information.PebBaseAddress, sizeof(PEB), process);
			address = peb.Ldr;
		} else {
			// Compile some assembly here to read the PEB's address from fs:[0x30] (32 bit) or gs:[0x60] (64-bit)
		}
	}

	LDR_DATA loader = *MemoryWrapper<LDR_DATA>{address, sizeof(LDR_DATA), process};
	auto flink = loader.InLoadOrderModuleList.Flink;
	while(flink){
		LDR_ENTRY entry = *MemoryWrapper<LDR_ENTRY>{flink, sizeof(LDR_ENTRY), process};
		LoadedImages.emplace_back(Loaded_Image{ entry, process });
		flink = entry.InLoadOrderModuleList.Flink;
	}
}