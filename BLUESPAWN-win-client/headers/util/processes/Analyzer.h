#include <Windows.h>
#include <winternl.h>

#include <memory>
#include <functional>

#define ALLOCATE(name, size)                                                             \
    LPVOID name = VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); \
    std::unique_ptr<VOID, std::function<void(LPVOID)>> name##ScopeGuard{ name, [](LPVOID ptr){ VirtualFree(ptr, 0, MEM_RELEASE); } };

#define CREATE_HANDLE(name, ...) \
    HANDLE name = __VA_ARGS__;   \
    std::unique_ptr<VOID, std::function<void(HANDLE)>> name##ScopeGuard{ name, [](HANDLE ptr){ CloseHandle(ptr); } };

#define IMAGE_SECTION_INVALID         0x1000
#define IMAGE_FILE_INVALID            0x2000
#define IMAGE_LOADER_INVALID          0x4000

#define ERROR_OCCURED                 0x80000000

#define ADDRESS_NOT_IN_IMAGE_SECTION  IMAGE_SECTION_INVALID | 0x1
#define IMAGE_DOES_NOT_MATCH_FILE     IMAGE_SECTION_INVALID | 0x2
#define EXECUTION_NOT_IN_TEXT_SECTION IMAGE_SECTION_INVALID | 0x4
#define IMAGE_HEADERS_MISMATCH        IMAGE_SECTION_INVALID | 0x8

#define IMAGE_FILE_NOT_SIGNED         IMAGE_FILE_INVALID    | 0x1
#define IMAGE_FILE_NOT_FOUND          IMAGE_FILE_INVALID    | 0x2

#define IMAGE_LOADER_NAME_MISMATCH    IMAGE_LOADER_INVALID  | 0x1
#define IMAGE_LOADER_SIZE_MISMATCH    IMAGE_LOADER_INVALID  | 0x2

#define FAIL_IF_INVALID_HANDLE(name, ...)          \
    CREATE_HANDLE(name, __VA_ARGS__);              \
    if(name == INVALID_HANDLE_VALUE || name == 0){ \
        return ERROR_OCCURED | GetLastError();     \
    }

#define FAIL_IF_FALSE(...)                     \
    if(!(__VA_ARGS__)){                        \
        return ERROR_OCCURED | GetLastError(); \
	}

#define FAIL_IF_NOT_SUCCESS(...)     \
    {                                \
        STATUS status = __VA_ARGS__; \
        if(status != ERROR_SUCCESS)  \
             return status;          \
    }

typedef unsigned __int32 STATUS;

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

class Analyzer {
public:
	STATUS ValidateThread(HANDLE hThread, HANDLE hProcess);
	STATUS ValidateProcess(HANDLE hProcess);
	STATUS ValidateAddress(HANDLE hProcess, LPVOID lpAddress);

	STATUS ValidateAddressInImage(HANDLE hProcess, LPVOID lpAddress, LPVOID* lpBaseAddress);
	STATUS ValidateFile(HANDLE hFile);
	STATUS ValidateTextExecution(HANDLE hProcess, LPVOID lpAddress, LPVOID lpBaseAddress);
	STATUS ValidateLoader(HANDLE process, LPVOID BaseAddress, HANDLE hFile);
	STATUS ValidateMatchesFile(HANDLE hProcess, HANDLE hFile, LPVOID lpBaseAddress);
	STATUS ValidateImageSection(HANDLE hProcess, LPVOID lpAddress, PHANDLE hFile);
};