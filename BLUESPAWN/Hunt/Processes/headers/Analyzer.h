#include <Windows.h>

#include <memory>
#include <functional>

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
	int ValidateThread(HANDLE hThread, HANDLE hProcess);
	int ValidateProcess(HANDLE hProcess);
	int ValidateAddress(HANDLE hProcess, LPVOID lpAddress);

	int ValidateAddressInImage(HANDLE hProcess, LPVOID lpAddress, LPVOID* lpBaseAddress);
	int ValidateFile(HANDLE hFile);
	int ValidateTextExecution(HANDLE hProcess, LPVOID lpAddress, LPVOID lpBaseAddress);
	int ValidateLoader(HANDLE process, LPVOID BaseAddress, HANDLE file);
	int ValidateMatchesFile(HANDLE hProcess, HANDLE hFile, LPVOID lpBaseAddress);
	std::unique_ptr<VOID, std::function<VOID(HANDLE)>> ValidateImageSection(HANDLE hProcess, LPVOID lpAddress);
};

