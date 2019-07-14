#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <DbgHelp.h>
#include <Psapi.h>
#include <SoftPub.h>
#include "Analyzer.h"

#define FAIL_IF_INVALID_HANDLE(name, ...) \
    HANDLE name = __VA_ARGS__;            \
    if(name == INVALID_HANDLE_VALUE){     \
        return FALSE;                     \
    }

#define FAIL_IF_FALSE(...) \
    if(!(__VA_ARGS__)){    \
        return FALSE;      \
	}

#define LEAVE_IF_FALSE(...) \
    if(!(__VA_ARGS__)){     \
        ret = FALSE;        \
        __leave;            \
	}

int Analyzer::ValidateProcess(HANDLE hProcess){
	FAIL_IF_INVALID_HANDLE(hThreadSnapshot, CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
	
	int PID = GetProcessId(hProcess);

	int ret = TRUE;

	__try {
		THREADENTRY32 ThreadEntry = { sizeof(THREADENTRY32), 0 };

		LEAVE_IF_FALSE(Thread32First(hThreadSnapshot, &ThreadEntry));

		do if(ThreadEntry.th32OwnerProcessID == PID){
			HANDLE hThread;
			LEAVE_IF_FALSE(hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadEntry.th32ThreadID));
			LEAVE_IF_FALSE(ValidateThread(hThread, hProcess));
		} while(Thread32Next(hThreadSnapshot, &ThreadEntry));

	} __finally {
		CloseHandle(hThreadSnapshot);
	}
	return ret;
}

int Analyzer::ValidateThread(HANDLE hThread, HANDLE hProcess){
	// TODO: iterate call stack, pass address to ValidateAddress
	return 0;
}

int Analyzer::ValidateAddress(HANDLE hProcess, LPVOID lpAddress){
	HANDLE hFile;
	LPVOID lpBaseAddress;

	FAIL_IF_FALSE(ValidateAddressInImage(hProcess, lpAddress, &lpBaseAddress));
	FAIL_IF_FALSE(ValidateTextExecution(hProcess, lpAddress, lpBaseAddress));
	FAIL_IF_FALSE(ValidateChecksum(hProcess, lpBaseAddress));
	FAIL_IF_FALSE(ValidateImageSection(hProcess, lpBaseAddress, &hFile));
	FAIL_IF_FALSE(ValidateMatchesFile(hProcess, hFile, lpBaseAddress));
	FAIL_IF_FALSE(ValidateFile(hFile));
	FAIL_IF_FALSE(ValidateLoader(hProcess, lpBaseAddress, hFile));

	return TRUE;
}

int Analyzer::ValidateAddressInImage(HANDLE hProcess, LPVOID lpAddress, LPVOID* lpBaseAddress){
	PROCESS_BASIC_INFORMATION pbi;
	FAIL_IF_FALSE(!NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr));

	PEB peb;
	FAIL_IF_FALSE(ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr));

	PLDR_DATA loader = (PLDR_DATA) peb.Ldr;
	LDR_ENTRY image;
	FAIL_IF_FALSE(ReadProcessMemory(hProcess, loader, &image, sizeof(image), nullptr));

	do {
		if((SIZE_T) lpAddress >= (SIZE_T) image.DllBase && (SIZE_T) lpAddress < (SIZE_T) image.DllBase + image.SizeOfImage){
			*lpBaseAddress = image.DllBase;
			return TRUE;
		}
	} while(ReadProcessMemory(hProcess, image.InLoadOrderModuleList.Flink, &image, sizeof(image), nullptr));

	return FALSE;
}

int Analyzer::ValidateTextExecution(HANDLE hProcess, LPVOID lpAddress, LPVOID lpBaseAddress){
	IMAGE_DOS_HEADER DOSHeader;
	FAIL_IF_FALSE(ReadProcessMemory(hProcess, lpBaseAddress, &DOSHeader, sizeof(DOSHeader), nullptr));

	IMAGE_NT_HEADERS NTHeaders;
	FAIL_IF_FALSE(ReadProcessMemory(hProcess, (LPVOID)((SIZE_T) lpBaseAddress + DOSHeader.e_lfanew),
		                            &NTHeaders, sizeof(NTHeaders), nullptr));

	PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((SIZE_T) lpBaseAddress + DOSHeader.e_lfanew +
		                                                     sizeof(NTHeaders));

	for(int i = 0; i < NTHeaders.FileHeader.NumberOfSections; i++){
		IMAGE_SECTION_HEADER section;
		FAIL_IF_FALSE(ReadProcessMemory(hProcess, &sections[i], &section, sizeof(section), nullptr));

		if(!strcmp((char*) section.Name, ".text")){
			SIZE_T rva = section.VirtualAddress;
			SIZE_T va = rva + (SIZE_T) lpBaseAddress;
			return (SIZE_T) lpAddress >= va && (SIZE_T) lpAddress < va + section.SizeOfRawData;
		}
	}
	
	return FALSE;
}

int Analyzer::ValidateImageSection(HANDLE hProcess, LPVOID lpBaseAddress, PHANDLE hFile){
	char lpFileName[256];
	FAIL_IF_FALSE(GetMappedFileNameA(hProcess, lpBaseAddress, lpFileName, 256));

	FAIL_IF_INVALID_HANDLE(file, CreateFileA(lpFileName, GENERIC_READ, FILE_SHARE_READ, nullptr, 
		                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
	FAIL_IF_FALSE(file);
	
	*hFile = file;

	return TRUE;
}

int Analyzer::ValidateMatchesFile(HANDLE hProcess, HANDLE hFile, LPVOID lpBaseAddress){
	//For now, just do the text section and headers. In the future, roll back the relocations
	//and imports, then compare everything to the file

	int ret = FALSE;//Think of this as rax

	DWORD dwFileSize = GetFileSize(hFile, nullptr);
	FAIL_IF_FALSE(dwFileSize);

	LPVOID lpFileContents = LocalAlloc(MEM_RESERVE | MEM_COMMIT, dwFileSize);
	FAIL_IF_FALSE(lpFileContents);

	__try {
		LEAVE_IF_FALSE(ReadFile(hFile, lpFileContents, dwFileSize, nullptr, nullptr));

		PIMAGE_DOS_HEADER pFileDOSHeader = (PIMAGE_DOS_HEADER) lpFileContents;
		PIMAGE_NT_HEADERS pFileNtHeader = (PIMAGE_NT_HEADERS) ((SIZE_T) lpFileContents + pFileDOSHeader->e_lfanew);

		IMAGE_DOS_HEADER RemoteDOSHeader;
		LEAVE_IF_FALSE(ReadProcessMemory(hProcess, lpBaseAddress, &RemoteDOSHeader, sizeof(RemoteDOSHeader), nullptr));

		IMAGE_NT_HEADERS RemoteNTHeaders;
		LEAVE_IF_FALSE(ReadProcessMemory(hProcess, (LPVOID) ((SIZE_T) lpBaseAddress + RemoteDOSHeader.e_lfanew),
			&RemoteNTHeaders, sizeof(RemoteNTHeaders), nullptr));

		LPVOID lpRemoteImage = LocalAlloc(MEM_RESERVE | MEM_COMMIT, RemoteNTHeaders.OptionalHeader.SizeOfImage);
		LEAVE_IF_FALSE(lpRemoteImage);

		__try {
			LEAVE_IF_FALSE(ReadProcessMemory(hProcess, lpBaseAddress, lpRemoteImage, RemoteNTHeaders.OptionalHeader.SizeOfImage, nullptr));
			LEAVE_IF_FALSE(!memcmp(lpFileContents, lpRemoteImage, pFileNtHeader->OptionalHeader.SizeOfHeaders));

			PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)(pFileDOSHeader->e_lfanew + sizeof(PIMAGE_NT_HEADERS));

			for(int i = 0; i < pFileNtHeader->FileHeader.NumberOfSections; i++){
				if(!strcmp((char*) sections[i].Name, ".text")){
					LPVOID lpFileTextSection = (LPVOID) ((SIZE_T) lpFileContents + sections[i].PointerToRawData);
					LPVOID lpRemoteTextSection = (LPVOID) ((SIZE_T) lpRemoteImage + sections[i].VirtualAddress);
					ret = !memcmp(lpFileTextSection, lpRemoteTextSection, sections[i].SizeOfRawData);
					__leave;
				}
			}
		} __finally {
			LocalFree(lpRemoteImage);
		}
	} __finally {
		LocalFree(lpFileContents);
	}

	return ret;
}

int Analyzer::ValidateFile(HANDLE hFile){
	WCHAR strFileName[256];
	FAIL_IF_FALSE(GetFinalPathNameByHandleW(hFile, strFileName, 256, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS));

	WINTRUST_FILE_INFO FileData;
	memset(&FileData, 0, sizeof(FileData));
	FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileData.pcwszFilePath = strFileName;
	FileData.hFile = hFile;
	FileData.pgKnownSubject = NULL;

	GUID verification = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	WINTRUST_DATA WinTrustData;
	memset(&WinTrustData, 0, sizeof(WinTrustData));

	WinTrustData.cbStruct = sizeof(WinTrustData);
	WinTrustData.pPolicyCallbackData = NULL;
	WinTrustData.pSIPClientData = NULL;
	WinTrustData.dwUIChoice = WTD_UI_NONE;
	WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
	WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	WinTrustData.hWVTStateData = NULL;
	WinTrustData.pwszURLReference = NULL;
	WinTrustData.dwUIContext = 0;
	WinTrustData.pFile = &FileData;

	LONG result = WinVerifyTrust((HWND) INVALID_HANDLE_VALUE, &verification, &WinTrustData);

	return result == 0;
}

int Analyzer::ValidateLoader(HANDLE hProcess, LPVOID lpBaseAddress, HANDLE hFile){
	PROCESS_BASIC_INFORMATION pbi;
	FAIL_IF_FALSE(!NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr));

	PEB peb;
	FAIL_IF_FALSE(ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr));

	PLDR_DATA loader = (PLDR_DATA) peb.Ldr;
	LDR_ENTRY image;
	FAIL_IF_FALSE(ReadProcessMemory(hProcess, loader, &image, sizeof(image), nullptr));


	WCHAR strFileName[256];
	FAIL_IF_FALSE(GetFinalPathNameByHandleW(hFile, strFileName, 256, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS));

	do {
		if(lpBaseAddress == image.DllBase){
			return !wcscmp(image.FullDllName.Buffer, strFileName);
		}
	} while(ReadProcessMemory(hProcess, image.InLoadOrderModuleList.Flink, &image, sizeof(image), nullptr));

	return FALSE;
}