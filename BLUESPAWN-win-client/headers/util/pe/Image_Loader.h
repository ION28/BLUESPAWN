#pragma once

#include <Windows.h>

#include "util/wrappers.hpp"
#include "util/DynamicLinker.h"

#include "util/pe/PE_Image.h"

DEFINE_FUNCTION(NTSTATUS, NtQueryInformationProcess, __kernel_entry NTAPI, IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInnformationLength,
	OUT PULONG ReturnLength);

typedef struct _UNICODE_STRING32 {
	USHORT Length;
	USHORT MaximumLength;
	DWORD Buffer; // PWSTR
} UNICODE_STRING32, *PUNICODE_STRING32;

typedef struct _LDR_ENTRY32 {
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	DWORD DllBase;    // LPVOID
	DWORD EntryPoint; // LPVOID
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	union {
		ULONG TimeDateStamp;
		DWORD LoadedImports;
	};
} LDR_ENTRY32, *PLDR_ENTRY32;

typedef struct _LDR_DATA32 {
	ULONG Length;
	BOOLEAN Initialized;
	DWORD SsHandle;         // PVOID
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	DWORD EntryInProgress;  // PVOID
	BOOLEAN ShutdownInProgress;
	DWORD ShutdownThreadId; // HANDLE
} LDR_DATA32, *PLDR_DATA32;

typedef struct _UNICODE_STRING64 {
	USHORT Length;
	USHORT MaximumLength;
	DWORD64 Buffer; // PWSTR
} UNICODE_STRING64, * PUNICODE_STRING64;

typedef struct _LDR_ENTRY64 {
	LIST_ENTRY64 InLoadOrderModuleList;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
	DWORD64 DllBase;    // LPVOID
	DWORD64 EntryPoint; // LPVOID
	ULONG SizeOfImage;
	UNICODE_STRING64 FullDllName;
	UNICODE_STRING64 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY64 HashLinks; 
	union {
		ULONG TimeDateStamp;
		DWORD64 LoadedImports;
	};
} LDR_ENTRY64, *PLDR_ENTRY64;

typedef struct _LDR_DATA64 {
	ULONG Length;
	BOOLEAN Initialized;
	DWORD64 SsHandle;         // PVOID
	LIST_ENTRY64 InLoadOrderModuleList;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
	DWORD64 EntryInProgress;  // PVOID
	BOOLEAN ShutdownInProgress;
	DWORD64 ShutdownThreadId; // HANDLE
} LDR_DATA64, * PLDR_DATA64;

struct Loaded_Image64 {
	HandleWrapper process;
	std::wstring ImageName;
	std::wstring ImagePath;
	DWORD ImageSize;
	DWORD64 ImageAddress;
	DWORD64 EntryPoint;

	Loaded_Image64(const LDR_ENTRY64& entry, const HandleWrapper& process);
};

struct Loaded_Image32 {
	HandleWrapper process;
	std::wstring ImageName;
	std::wstring ImagePath;
	DWORD ImageSize;
	DWORD ImageAddress;
	DWORD EntryPoint;

	Loaded_Image32(const LDR_ENTRY32& entry, const HandleWrapper& process);
};

struct Loaded_Image {
	Architecture arch;

	std::optional<Loaded_Image32> image32;
	std::optional<Loaded_Image64> image64;

	Loaded_Image(const LDR_ENTRY32& entry, const HandleWrapper& process);
	Loaded_Image(const LDR_ENTRY64& entry, const HandleWrapper& process);
	
	std::wstring GetName();
};

class Image_Loader {
public:
	std::vector<Loaded_Image> LoadedImages;
	Architecture arch;
	const HandleWrapper& process;
	DWORD64 address;

	Image_Loader(const HandleWrapper& process = GetCurrentProcess());

	bool ContainsImage(const std::wstring& name) const;

	std::optional<Loaded_Image> GetImageInfo(const std::wstring& name) const;

	std::optional<Loaded_Image> GetAssociatedImage(LPVOID address) const;
};

