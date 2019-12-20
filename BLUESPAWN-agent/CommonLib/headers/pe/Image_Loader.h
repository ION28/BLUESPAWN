#pragma once

#include <Windows.h>

#include "common/wrappers.hpp"
#include "common/DynamicLinker.h"

#include "PE_Image.h"

DEFINE_FUNCTION(NTSTATUS, NtQueryInformationProcess, __kernel_entry NTAPI, IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInnformationLength,
	OUT PULONG ReturnLength);

typedef struct _LDR_ENTRY {
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
} LDR_ENTRY, *PLDR_ENTRY;

typedef struct _LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} LDR_DATA, *PLDR_DATA;

struct Loaded_Image {
	std::wstring ImageName;
	std::wstring ImagePath;
	DWORD ImageSize;
	DWORD64 ImageAddress;
	DWORD64 EntryPoint;
	bool ImportsParsed;

	Loaded_Image(const LDR_ENTRY& entry, const HandleWrapper& process, bool imported = true);
	Loaded_Image(const PE_Image& image, bool importsFinished = false, const std::wstring& ImagePath = L"");

	PE_Image GetImage();
	LDR_ENTRY CreateLoaderEntry();
};

class Image_Loader {
public:
	std::vector<Loaded_Image> LoadedImages;
	const HandleWrapper& process;

	Image_Loader(const HandleWrapper& process = GetCurrentProcess(), LPVOID LoaderAddress = nullptr);

	bool AddImage(const Loaded_Image& image);

	bool ContainsImage(const std::wstring& name);

	bool RemoveImage(const Loaded_Image& image);

	Loaded_Image GetImageInfo(const std::wstring& name);
};

