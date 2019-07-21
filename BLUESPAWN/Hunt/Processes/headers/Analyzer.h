#include <Windows.h>

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
	int ValidateAddress(HANDLE hProcess, LPVOID lpAddress);
	int ValidateAddressInImage(HANDLE hProcess, LPVOID lpAddress, LPVOID* lpBaseAddress);
	int ValidateFile(HANDLE hFile);
	int ValidateTextExecution(HANDLE hProcess, LPVOID lpAddress, LPVOID lpBaseAddress);
	int ValidateChecksum(HANDLE hProcess, LPVOID BaseAddress);
	int ValidateLoader(HANDLE process, LPVOID BaseAddress, HANDLE file);
	int ValidateMatchesFile(HANDLE hProcess, HANDLE hFile, LPVOID lpBaseAddress);
	int ValidateImageSection(HANDLE hProcess, LPVOID lpAddress, PHANDLE phFile);
	int ValidateThread(HANDLE hThread, HANDLE hProcess);
	int ValidateProcess(HANDLE hProcess);
};

