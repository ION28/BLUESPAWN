#include "util/pe/Image_Loader.h"
#include "util/log/Log.h"

#include <functional>

LINK_FUNCTION(NtQueryInformationProcess, NTDLL.dll);

bool CompareStrings(const UNICODE_STRING32& s1, const HandleWrapper& process1, const UNICODE_STRING32& s2, const HandleWrapper& process2){
	if(s1.Length != s2.Length)
		return false;
	return MemoryWrapper<>(reinterpret_cast<LPVOID>(s1.Buffer), s1.Length * 2 + 2, process1).ReadWstring() ==
		MemoryWrapper<>(reinterpret_cast<LPVOID>(s2.Buffer), s2.Length * 2 + 2, process2).ReadWstring();
}
bool CompareStrings(const UNICODE_STRING64& s1, const HandleWrapper& process1, const UNICODE_STRING64& s2, const HandleWrapper& process2){
	if(s1.Length != s2.Length)
		return false;
	return MemoryWrapper<>(reinterpret_cast<LPVOID>(s1.Buffer), s1.Length * 2 + 2, process1).ReadWstring() ==
		MemoryWrapper<>(reinterpret_cast<LPVOID>(s2.Buffer), s2.Length * 2 + 2, process2).ReadWstring();
}
bool CompareStrings(const UNICODE_STRING32& s1, const HandleWrapper& process1, const std::wstring& s2){
	if(s1.Length != s2.length())
		return false;
	return MemoryWrapper<>(reinterpret_cast<LPVOID>(s1.Buffer), s1.Length * 2 + 2, process1).ReadWstring() == s2;
}
bool CompareStrings(const UNICODE_STRING64& s1, const HandleWrapper& process1, const std::wstring& s2){
	if(s1.Length != s2.length())
		return false;
	return MemoryWrapper<>(reinterpret_cast<LPVOID>(s1.Buffer), s1.Length * 2 + 2, process1).ReadWstring() == s2;
}

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
	ImagePath{ MemoryWrapper<WCHAR>{ reinterpret_cast<LPVOID>(entry.FullDllName.Buffer), static_cast<SIZE_T>(entry.FullDllName.Length + 1), 
	    process }.ReadWstring() },
	ImageName{ MemoryWrapper<WCHAR>{ reinterpret_cast<LPVOID>(entry.BaseDllName.Buffer), static_cast<SIZE_T>(entry.BaseDllName.Length + 1), 
	    process }.ReadWstring() },
	ImageSize{ entry.SizeOfImage },
	ImportsParsed{ imported },
	process{ process }{}

Image_Loader::Image_Loader(const HandleWrapper& process) : 
	process{ process }, LoadedImages{}{
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
		auto FirstAddress = MemoryWrapper<LDR_DATA64>{ reinterpret_cast<LPVOID>(address), sizeof(LDR_DATA64), process }->InLoadOrderModuleList.Flink;
		auto entry = *MemoryWrapper<LDR_ENTRY64>{reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(FirstAddress)), sizeof(LDR_ENTRY64), process};
		while(entry.EntryPoint){
			LoadedImages.emplace_back(Loaded_Image{ entry, process });
			entry = *MemoryWrapper<LDR_ENTRY64>{reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(entry.InLoadOrderModuleList.Flink)), sizeof(LDR_ENTRY64), process};
		}
	} else {
		auto FirstAddress = MemoryWrapper<LDR_DATA32>{ reinterpret_cast<LPVOID>(address), sizeof(LDR_DATA32), process }->InLoadOrderModuleList.Flink;
		auto entry = *MemoryWrapper<LDR_ENTRY32>{reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(FirstAddress)), sizeof(LDR_ENTRY32), process};
		while(entry.EntryPoint){
			LoadedImages.emplace_back(Loaded_Image{ entry, process });
			entry = *MemoryWrapper<LDR_ENTRY32>{reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(entry.InLoadOrderModuleList.Flink)), sizeof(LDR_ENTRY32), process};
		}
	}
}

bool Image_Loader::AddImage(const Loaded_Image& image){
	if(image.arch != arch){
		return false;
	}

	if(ContainsImage(image.arch == x64 ? image.image64->ImageName : image.image32->ImageName)){
		return true;
	}

	if(arch == x64){
		auto Loader = *MemoryWrapper<LDR_DATA64>{ reinterpret_cast<LPVOID>(address), sizeof(LDR_DATA64), process };
		auto LastEntry = *MemoryWrapper<LDR_ENTRY64>{ reinterpret_cast<LPVOID>(Loader.InLoadOrderModuleList.Blink), sizeof(LDR_ENTRY64), process };
		auto DllNameMemory = VirtualAllocEx(process, nullptr, (image.image64->ImageName.length() + image.image64->ImagePath.length()) * 2 + 4, 
			MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		MemoryWrapper<>(DllNameMemory).Write(reinterpret_cast<LPCSTR>(image.image64->ImageName.c_str()), image.image64->ImageName.length() * 2, 0);
		MemoryWrapper<>(DllNameMemory).Write(reinterpret_cast<LPCSTR>(image.image64->ImagePath.c_str()), image.image64->ImagePath.length() * 2, 
			image.image64->ImageName.length() * 2 + 2);
		/*auto Entry = LDR_ENTRY64{
			LIST_ENTRY64{ LastEntry.InLoadOrderModuleList.Flink, Loader.InLoadOrderModuleList.Blink },
			LIST_ENTRY64{ LastEntry.InMemoryOrderModuleList.Flink, Loader.InMemoryOrderModuleList.Blink },
			LIST_ENTRY64{ LastEntry.InInitializationOrderModuleList.Flink, Loader.InInitializationOrderModuleList.Blink },
			image.image64->ImageAddress,
			image.image64->EntryPoint,
			image.image64->ImageSize,
			UNICODE_STRING64{ image.image64->ImageName.length(), image.image64->ImageName.length(), reinterpret_cast<DWORD64>(DllNameMemory) },
			UNICODE_STRING64{
				image.image64->ImagePath.length(),
				image.image64->ImagePath.length(),
				reinterpret_cast<DWORD64>(DllNameMemory) + image.image64->ImageName.length() * 2 + 2
			},
			LastEntry.Flags,
			1,
			LastEntry.TlsIndex + 1,
			LIST_ENTRY64{ 0, 0 },
			0
		};*/
		LoadedImages.emplace_back(image);
	} else {
		auto FirstAddress = MemoryWrapper<LDR_DATA32>{ reinterpret_cast<LPVOID>(address), sizeof(LDR_DATA32), process }->InLoadOrderModuleList.Flink;
		auto entry = *MemoryWrapper<LDR_ENTRY32>{reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(FirstAddress)), sizeof(LDR_ENTRY32), process};
		while(entry.EntryPoint){
			LoadedImages.emplace_back(Loaded_Image{ entry, process });
			entry = *MemoryWrapper<LDR_ENTRY32>{reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(entry.InLoadOrderModuleList.Flink)), sizeof(LDR_ENTRY32), process};
		}
	}
	return false;
}

bool Image_Loader::RemoveImage(const Loaded_Image& image){
	if(arch != image.arch){
		return false;
	}

	if(arch == x64){
		auto FirstAddress = MemoryWrapper<LDR_DATA64>{ reinterpret_cast<LPVOID>(address), sizeof(LDR_DATA64), process }->InLoadOrderModuleList.Flink;
		auto entry = *MemoryWrapper<LDR_ENTRY64>{reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(FirstAddress)), sizeof(LDR_ENTRY64), process};
		while(entry.EntryPoint){
			if(CompareStrings(entry.BaseDllName, process, image.image64->ImageName)){
				//*MemoryWrapper<LDR_ENTRY64>{reinterpret_cast<LPVOID>(entry.InInitializationOrderModuleList.Blink), sizeof(LDR_ENTRY64), process}
			}
			entry = *MemoryWrapper<LDR_ENTRY64>{reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(entry.InLoadOrderModuleList.Flink)), sizeof(LDR_ENTRY64), process};
		}
	} else {
		auto FirstAddress = MemoryWrapper<LDR_DATA32>{ reinterpret_cast<LPVOID>(address), sizeof(LDR_DATA32), process }->InLoadOrderModuleList.Flink;
		auto entry = *MemoryWrapper<LDR_ENTRY32>{reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(FirstAddress)), sizeof(LDR_ENTRY32), process};
		while(entry.EntryPoint){
			LoadedImages.emplace_back(Loaded_Image{ entry, process });
			entry = *MemoryWrapper<LDR_ENTRY32>{reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(entry.InLoadOrderModuleList.Flink)), sizeof(LDR_ENTRY32), process};
		}
	}

	return false;
}