#include "util/pe/Image_Loader.h"
#include "util/log/Log.h"

#include <functional>

LINK_FUNCTION(NtQueryInformationProcess, NTDLL.dll);

bool CompareStrings(const UNICODE_STRING32& s1, const HandleWrapper& process1, const UNICODE_STRING32& s2, const HandleWrapper& process2){
	if(s1.Length != s2.Length)
		return false;
	return MemoryWrapper<>(reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(s1.Buffer)), s1.Length * 2 + 2, process1).ReadWstring() ==
		MemoryWrapper<>(reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(s1.Buffer)), s2.Length * 2 + 2, process2).ReadWstring();
}

bool CompareStrings(const UNICODE_STRING64& s1, const HandleWrapper& process1, const UNICODE_STRING64& s2, const HandleWrapper& process2){
	if(s1.Length != s2.Length)
		return false;
	return MemoryWrapper<>(reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(s1.Buffer)), s1.Length * 2 + 2, process1).ReadWstring() ==
		MemoryWrapper<>(reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(s2.Buffer)), s2.Length * 2 + 2, process2).ReadWstring();
}
bool CompareStrings(const UNICODE_STRING32& s1, const HandleWrapper& process1, const std::wstring& s2){
	if(s1.Length != s2.length())
		return false;
	return MemoryWrapper<>(reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(s1.Buffer)), s1.Length * 2 + 2, process1).ReadWstring() == s2;
}
bool CompareStrings(const UNICODE_STRING64& s1, const HandleWrapper& process1, const std::wstring& s2){
	if(s1.Length != s2.length())
		return false;
	return MemoryWrapper<>(reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(s1.Buffer)), s1.Length * 2 + 2, process1).ReadWstring() == s2;
}

Loaded_Image32::Loaded_Image32(const LDR_ENTRY32& entry, const HandleWrapper& process) :
	EntryPoint{ entry.EntryPoint },
	ImageAddress{ entry.DllBase },
	ImagePath{ MemoryWrapper<WCHAR>{ reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(entry.FullDllName.Buffer)), 
	    static_cast<SIZE_T>(entry.FullDllName.Length + 1), process }.ReadWstring() },
	ImageName{ MemoryWrapper<WCHAR>{ reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(entry.BaseDllName.Buffer)),
	    static_cast<SIZE_T>(entry.BaseDllName.Length + 1), process }.ReadWstring() },
	ImageSize{ entry.SizeOfImage },
	process{ process }{}

Loaded_Image64::Loaded_Image64(const LDR_ENTRY64& entry, const HandleWrapper& process) :
	EntryPoint{ entry.EntryPoint },
	ImageAddress{ entry.DllBase },
	ImagePath{ MemoryWrapper<WCHAR>{ reinterpret_cast<LPVOID>(entry.FullDllName.Buffer), static_cast<SIZE_T>(entry.FullDllName.Length + 1), 
	    process }.ReadWstring() },
	ImageName{ MemoryWrapper<WCHAR>{ reinterpret_cast<LPVOID>(entry.BaseDllName.Buffer), static_cast<SIZE_T>(entry.BaseDllName.Length + 1), 
	    process }.ReadWstring() },
	ImageSize{ entry.SizeOfImage },
	process{ process }{}

Loaded_Image::Loaded_Image(const LDR_ENTRY32& entry, const HandleWrapper& process) :
	arch{ Architecture::x86 },
	image32{ Loaded_Image32{ entry, process } },
	image64{ std::nullopt } {}

Loaded_Image::Loaded_Image(const LDR_ENTRY64& entry, const HandleWrapper& process) :
	arch{ Architecture::x64 },
	image64{ Loaded_Image64{ entry, process } },
	image32{ std::nullopt } {}

std::wstring Loaded_Image::GetName(){
	return arch == x64 ? image64->ImageName : image32->ImageName;
}

Image_Loader::Image_Loader(const HandleWrapper& process) : 
	process{ process }, LoadedImages{}{
	if(process){
		PROCESS_BASIC_INFORMATION information{};
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

bool Image_Loader::ContainsImage(const std::wstring& wImageName) const {
	for(auto image : LoadedImages){
		if(image.GetName() == wImageName){
			return true;
		}
	}
	return false;
}


std::optional<Loaded_Image> Image_Loader::GetImageInfo(const std::wstring& wImageName) const {
	for(auto image : LoadedImages){
		if(image.GetName() == wImageName){
			return image;
		}
	}
	return std::nullopt;
}

std::optional<Loaded_Image> Image_Loader::GetAssociatedImage(LPVOID address) const {
	for(auto image : LoadedImages){
		auto addr{ reinterpret_cast<ULONG_PTR>(address) };
		if(image.arch == x86 && static_cast<DWORD>(addr) >= image.image32->ImageAddress && 
		   static_cast<DWORD>(addr) < image.image32->ImageAddress + image.image32->ImageSize &&
		   static_cast<DWORD64>(addr) == static_cast<DWORD>(addr)){
			return image;
		} else if(image.arch == x64 && static_cast<DWORD64>(addr) >= image.image64->ImageAddress &&
				  static_cast<DWORD64>(addr) < image.image64->ImageAddress + image.image64->ImageSize){
			return image;
		}
	}
	return std::nullopt;
}