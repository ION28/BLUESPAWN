#include "pe/Image_Loader.h"
#include "logging/Log.h"

#include <functional>

LINK_FUNCTION(NtQueryInformationProcess, NTDLL.dll);

Loaded_Image32::Loaded_Image32(const LDR_ENTRY32& entry, const HandleWrapper& process, bool imported) :
	EntryPoint{ entry.EntryPoint },
	ImageAddress{ entry.DllBase },
	ImagePath{ MemoryWrapper<WCHAR>{ reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(entry.FullDllName.Buffer)), 
	    static_cast<SIZE_T>(entry.FullDllName.Length + 1), process }.ReadWstring() },
	ImageName{ MemoryWrapper<WCHAR>{ reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(entry.BaseDllName.Buffer)),
	    static_cast<SIZE_T>(entry.BaseDllName.Length + 1), process }.ReadWstring() },
	ImageSize{ entry.SizeOfImage },
	ImportsParsed{ imported },
	process{ process }{}

Loaded_Image64::Loaded_Image64(const LDR_ENTRY64& entry, const HandleWrapper& process, bool imported) :
	EntryPoint{ entry.EntryPoint },
	ImageAddress{ entry.DllBase },
	ImagePath{ MemoryWrapper<WCHAR>{ reinterpret_cast<LPVOID>(entry.FullDllName.Buffer), static_cast<SIZE_T>(entry.FullDllName.Length + 1), process }.ReadWstring() },
	ImageName{ MemoryWrapper<WCHAR>{ reinterpret_cast<LPVOID>(entry.BaseDllName.Buffer), static_cast<SIZE_T>(entry.BaseDllName.Length + 1), process }.ReadWstring() },
	ImageSize{ entry.SizeOfImage },
	ImportsParsed{ imported },
	process{ process }{}

Image_Loader::Image_Loader(const HandleWrapper& process) : 
	process{ process }, LoadedImages{}{
	DWORD64 address;
	if(process){
		PROCESS_BASIC_INFORMATION information = {};
		NTSTATUS status = Linker::NtQueryInformationProcess(process, ProcessBasicInformation, &information, sizeof(information), nullptr);
		if(!NT_SUCCESS(status)){
			LOG_ERROR("Error " << status << " occured when finding the PEB of process " << process.Get());
		}
		BOOL wow64 = false;
		IsWow64Process(process, &wow64);

		if(wow64){
			arch = x86;
			address = *MemoryWrapper<DWORD>(information.PebBaseAddress, sizeof(DWORD) * 4, process).GetOffset(sizeof(DWORD) * 3);
		} else {
#ifdef _WIN64 
			arch = x64;
			address = *MemoryWrapper<DWORD64>(information.PebBaseAddress, sizeof(DWORD64) * 4, process).GetOffset(sizeof(DWORD64) * 3);
#else
			arch = x86;
			address = *MemoryWrapper<DWORD>(information.PebBaseAddress, sizeof(DWORD) * 4, process).GetOffset(sizeof(DWORD) * 3);
#endif
		}
	} else {
#ifdef _WIN64
		address = __readgsqword(0x60);
		arch = x64;
#else
		address = __readfsdword(0x30);
		arch = x86;
#endif
	}

	if(arch == x64){
		auto flink = MemoryWrapper<LDR_DATA64>{ reinterpret_cast<LPVOID>(address), sizeof(LDR_DATA64), process }->InLoadOrderModuleList.Flink;
		while(flink){
			LDR_ENTRY64 entry = *MemoryWrapper<LDR_ENTRY64>{reinterpret_cast<LPVOID>(flink), sizeof(LDR_ENTRY64), process};
			LoadedImages.emplace_back(Loaded_Image{ entry, process });
			flink = entry.InLoadOrderModuleList.Flink;
		}
	} else {
		auto flink = MemoryWrapper<LDR_DATA32>{ reinterpret_cast<LPVOID>(address), sizeof(LDR_DATA32), process }->InLoadOrderModuleList.Flink;
		while(flink){
			LDR_ENTRY32 entry = *MemoryWrapper<LDR_ENTRY32>{reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(flink)), sizeof(LDR_ENTRY32), process};
			LoadedImages.emplace_back(Loaded_Image{ entry, process });
			flink = entry.InLoadOrderModuleList.Flink;
		}
	}
}