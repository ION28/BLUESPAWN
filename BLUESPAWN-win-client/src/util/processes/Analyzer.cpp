#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <DbgHelp.h>
#include <Psapi.h>
#include <SoftPub.h>

#include "util/processes/Analyzer.h"

#include <iostream>

auto _NtQueryInformationProcess = (NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, LPVOID, ULONG, PULONG)) GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryInformationProcess");

STATUS Analyzer::ValidateProcess(HANDLE hProcess){
	//std::cout << "Validating process with PID " << GetProcessId(hProcess) << std::endl;

	FAIL_IF_INVALID_HANDLE(hThreadSnapshot, CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
	
	int PID = GetProcessId(hProcess);

	THREADENTRY32 ThreadEntry = { sizeof(THREADENTRY32), 0 };

	FAIL_IF_FALSE(Thread32First(hThreadSnapshot, &ThreadEntry));

	do if(ThreadEntry.th32OwnerProcessID == PID){
		FAIL_IF_INVALID_HANDLE(hThread, OpenThread(THREAD_ALL_ACCESS, false, ThreadEntry.th32ThreadID));
		FAIL_IF_NOT_SUCCESS(ValidateThread(hThread, hProcess));
	} while(Thread32Next(hThreadSnapshot, &ThreadEntry));

	return ERROR_SUCCESS;
}

STATUS Analyzer::ValidateThread(HANDLE hThread, HANDLE hProcess){
	//std::cout << "Validating thread " << GetThreadId(hThread) << " in process with PID " << GetProcessId(hProcess) << std::endl;
	CONTEXT context{};
	context.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &context);

	STACKFRAME64 stack{};
	stack.AddrPC.Mode = AddrModeFlat;
	stack.AddrStack.Mode = AddrModeFlat;
	stack.AddrFrame.Mode = AddrModeFlat;

#ifdef _WIN64
	stack.AddrPC.Offset = context.Rip;
	stack.AddrStack.Offset = context.Rsp;
	stack.AddrFrame.Offset = context.Rbp;

	FAIL_IF_NOT_SUCCESS(ValidateAddress(hProcess, (LPVOID) context.Rip))

	DWORD dwMachineType = IMAGE_FILE_MACHINE_AMD64;
	BOOL wow64 = false;
	IsWow64Process(hProcess, &wow64);
	if(wow64){
		dwMachineType = IMAGE_FILE_MACHINE_I386;
	}
#else
	stack.AddrPC.Offset = context.Eip;
	stack.AddrStack.Offset = context.Esp;
	stack.AddrFrame.Offset = context.Ebp;

	FAIL_IF_FALSE(ValidateAddress(hProcess, (LPVOID) context.Eip))

	DWORD dwMachineType = IMAGE_FILE_MACHINE_I386;
#endif

	while(StackWalk64(dwMachineType, hProcess, hThread, &stack, &context, nullptr, SymFunctionTableAccess64, SymGetModuleBase64, nullptr)){
		FAIL_IF_NOT_SUCCESS(ValidateAddress(hProcess, (LPVOID) stack.AddrPC.Offset));
	}

	return ERROR_SUCCESS;
}

STATUS Analyzer::ValidateAddress(HANDLE hProcess, LPVOID lpAddress){
	//std::cout << "Validating address " << lpAddress << std::endl;

	LPVOID lpBaseAddress{};
	FAIL_IF_NOT_SUCCESS(ValidateAddressInImage(hProcess, lpAddress, &lpBaseAddress));
	//std::cout << "Address is in image" << std::endl;

	FAIL_IF_NOT_SUCCESS(ValidateTextExecution(hProcess, lpAddress, lpBaseAddress));
	//std::cout << "Address is in .text section" << std::endl;

	HANDLE hFile{};
	FAIL_IF_NOT_SUCCESS(ValidateImageSection(hProcess, lpBaseAddress, &hFile));
	std::unique_ptr<VOID, std::function<void(HANDLE)>> hFileScopeGuard{ hFile, [](HANDLE ptr){ CloseHandle(ptr); } };
	//std::cout << "Address is in a valid memory-mapped file" << std::endl;

	FAIL_IF_NOT_SUCCESS(ValidateMatchesFile(hProcess, hFile, lpBaseAddress));
	//std::cout << "In-memory image matches file" << std::endl;

	FAIL_IF_NOT_SUCCESS(ValidateFile(hFile));
	//std::cout << "File is signed" << std::endl;

	FAIL_IF_NOT_SUCCESS(ValidateLoader(hProcess, lpBaseAddress, hFile));
	//std::cout << "Loader and image match" << std::endl;

	//std::cout << "Address has passed all checks" << std::endl << std::endl;

	return ERROR_SUCCESS;
}

STATUS Analyzer::ValidateAddressInImage(HANDLE hProcess, LPVOID lpAddress, LPVOID* lpBaseAddress){
	PROCESS_BASIC_INFORMATION pbi{};

	FAIL_IF_NOT_SUCCESS(_NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr));
	FAIL_IF_FALSE(pbi.PebBaseAddress);

	PEB peb{};
	FAIL_IF_FALSE(ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr));

	LDR_DATA loader{};
	FAIL_IF_FALSE(ReadProcessMemory(hProcess, peb.Ldr, &loader, sizeof(loader), nullptr));

	LDR_ENTRY image{};
	FAIL_IF_FALSE(ReadProcessMemory(hProcess, loader.InLoadOrderModuleList.Flink, &image, sizeof(image), nullptr));

	do {
		if(!image.DllBase){
			break;
		}
		if((SIZE_T) lpAddress >= (SIZE_T) image.DllBase && (SIZE_T) lpAddress < (SIZE_T) image.DllBase + image.SizeOfImage){
			*lpBaseAddress = image.DllBase;
			return ERROR_SUCCESS;
		}
	} while(ReadProcessMemory(hProcess, image.InLoadOrderModuleList.Flink, &image, sizeof(image), nullptr));

	std::cout << "Invalid address: " << lpAddress << std::endl;
	return ADDRESS_NOT_IN_IMAGE_SECTION;
}

STATUS Analyzer::ValidateTextExecution(HANDLE hProcess, LPVOID lpAddress, LPVOID lpBaseAddress){
	IMAGE_DOS_HEADER DOSHeader{};
	FAIL_IF_FALSE(ReadProcessMemory(hProcess, lpBaseAddress, &DOSHeader, sizeof(DOSHeader), nullptr));

	IMAGE_NT_HEADERS NTHeaders{};
	FAIL_IF_FALSE(ReadProcessMemory(hProcess, (LPVOID)((SIZE_T) lpBaseAddress + DOSHeader.e_lfanew),
		                            &NTHeaders, sizeof(NTHeaders), nullptr));

	PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((SIZE_T) lpBaseAddress + DOSHeader.e_lfanew +
		                                                     sizeof(NTHeaders));

	for(int i = 0; i < NTHeaders.FileHeader.NumberOfSections; i++){
		IMAGE_SECTION_HEADER section{};
		FAIL_IF_FALSE(ReadProcessMemory(hProcess, &sections[i], &section, sizeof(section), nullptr));

		if(!strcmp((char*) section.Name, ".text")){
			SIZE_T rva = section.VirtualAddress;
			SIZE_T va = rva + (SIZE_T) lpBaseAddress;
			bool in_text = (SIZE_T) lpAddress >= va && (SIZE_T) lpAddress < va + section.SizeOfRawData;
			if(!in_text){
				return EXECUTION_NOT_IN_TEXT_SECTION;
			}
			
			return ERROR_SUCCESS;
		}
	}
	
	return ERROR_NOT_FOUND;
}

STATUS Analyzer::ValidateImageSection(HANDLE hProcess, LPVOID lpBaseAddress, PHANDLE hFile){
	char lpFileName[256]{};
	if(!GetMappedFileNameA(hProcess, lpBaseAddress, lpFileName, 256)){
		return ADDRESS_NOT_IN_IMAGE_SECTION;
	}

	char* sFileName = PCHAR(lpFileName) + 21;
	sFileName[0] = 'C';
	sFileName[1] = ':';

	*hFile = CreateFileA(sFileName, GENERIC_READ, FILE_SHARE_READ, nullptr,
		                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if(!*hFile || *hFile == INVALID_HANDLE_VALUE){
		return IMAGE_FILE_NOT_FOUND;
	}

	return ERROR_SUCCESS;
}

STATUS Analyzer::ValidateMatchesFile(HANDLE hProcess, HANDLE hFile, LPVOID lpBaseAddress){
	//For now, just do the text section and headers. In the future, roll back the relocations
	//and imports, then compare everything to the file

	DWORD dwFileSize = GetFileSize(hFile, nullptr);
	FAIL_IF_FALSE(dwFileSize);

	ALLOCATE(lpFileContents, dwFileSize);

	FAIL_IF_FALSE(lpFileContents);

	FAIL_IF_FALSE(ReadFile(hFile, lpFileContents, dwFileSize, nullptr, nullptr));

	PIMAGE_DOS_HEADER pFileDOSHeader = (PIMAGE_DOS_HEADER) lpFileContents;
	PIMAGE_NT_HEADERS pFileNtHeader = (PIMAGE_NT_HEADERS) ((SIZE_T) lpFileContents + pFileDOSHeader->e_lfanew);
	pFileNtHeader->OptionalHeader.ImageBase = ULONG_PTR(lpBaseAddress);

	IMAGE_DOS_HEADER RemoteDOSHeader;
	FAIL_IF_FALSE(ReadProcessMemory(hProcess, lpBaseAddress, &RemoteDOSHeader, sizeof(RemoteDOSHeader), nullptr));

	IMAGE_NT_HEADERS RemoteNTHeaders;
	FAIL_IF_FALSE(ReadProcessMemory(hProcess, (LPVOID) ((SIZE_T) lpBaseAddress + RemoteDOSHeader.e_lfanew),
		&RemoteNTHeaders, sizeof(RemoteNTHeaders), nullptr));

	ALLOCATE(lpRemoteImage, RemoteNTHeaders.OptionalHeader.SizeOfImage);

	FAIL_IF_FALSE(lpRemoteImage);

	FAIL_IF_FALSE(ReadProcessMemory(hProcess, lpBaseAddress, lpRemoteImage, RemoteNTHeaders.OptionalHeader.SizeOfImage, nullptr));
	if(memcmp(lpFileContents, lpRemoteImage, pFileNtHeader->OptionalHeader.SizeOfHeaders)){
		return IMAGE_HEADERS_MISMATCH;
	}

	/*PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER) (ULONG_PTR(lpFileContents) + pFileDOSHeader->e_lfanew + sizeof(PIMAGE_NT_HEADERS));

	for(int i = 0; i < pFileNtHeader->FileHeader.NumberOfSections; i++){
		std::cout << "Reading section " << (char*) sections[i].Name << std::endl;
		if(!strcmp((char*) sections[i].Name, ".text")){
			LPVOID lpFileTextSection = (LPVOID) ((SIZE_T) lpFileContents + sections[i].PointerToRawData);
			LPVOID lpRemoteTextSection = (LPVOID) ((SIZE_T) lpRemoteImage + sections[i].VirtualAddress);
			if(memcmp(lpFileTextSection, lpRemoteTextSection, sections[i].SizeOfRawData)){
				return IMAGE_DOES_NOT_MATCH_FILE;
			}

			return ERROR_SUCCESS;
		}
	}*/

	return ERROR_SUCCESS;
}

STATUS Analyzer::ValidateFile(HANDLE hFile){
	WCHAR strFileName[256]{};
	FAIL_IF_FALSE(GetFinalPathNameByHandleW(hFile, strFileName, 256, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS));

	WINTRUST_FILE_INFO FileData{};
	FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileData.pcwszFilePath = strFileName;
	FileData.hFile = hFile;
	FileData.pgKnownSubject = NULL;

	GUID verification = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	WINTRUST_DATA WinTrustData{};

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
	if(result){
		return IMAGE_FILE_NOT_SIGNED;
	}

	return ERROR_SUCCESS;
}

STATUS Analyzer::ValidateLoader(HANDLE hProcess, LPVOID lpBaseAddress, HANDLE hFile){
	PROCESS_BASIC_INFORMATION pbi;

	FAIL_IF_NOT_SUCCESS(_NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr));

	PEB peb{};
	FAIL_IF_FALSE(ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr));

	LDR_DATA loader{};
	FAIL_IF_FALSE(ReadProcessMemory(hProcess, peb.Ldr, &loader, sizeof(loader), nullptr));

	LDR_ENTRY image{};
	FAIL_IF_FALSE(ReadProcessMemory(hProcess, loader.InLoadOrderModuleList.Flink, &image, sizeof(image), nullptr));

	WCHAR strFileName[256]{};
	FAIL_IF_FALSE(GetFinalPathNameByHandleW(hFile, strFileName, 256, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS));

	do {
		if(!image.DllBase){
			break;
		}
		if(lpBaseAddress == image.DllBase){
			WCHAR wstrLoaderImageName[256]{};
			FAIL_IF_FALSE(ReadProcessMemory(hProcess, image.FullDllName.Buffer, wstrLoaderImageName, image.FullDllName.Length, nullptr));

			bool bNameMismatch = _wcsicmp(wstrLoaderImageName, strFileName + 4);
			if(bNameMismatch){
				return IMAGE_LOADER_NAME_MISMATCH;
			}

			IMAGE_DOS_HEADER DOSHeader{};
			FAIL_IF_FALSE(ReadProcessMemory(hProcess, lpBaseAddress, &DOSHeader, sizeof(IMAGE_DOS_HEADER), nullptr));

			IMAGE_NT_HEADERS NTHeaders{};
			FAIL_IF_FALSE(ReadProcessMemory(hProcess, DOSHeader.e_lfanew + PCHAR(lpBaseAddress), &NTHeaders, sizeof(IMAGE_NT_HEADERS), nullptr));

			bool bSizeMismatch = image.SizeOfImage != NTHeaders.OptionalHeader.SizeOfImage;
			if(bSizeMismatch){
				return IMAGE_LOADER_SIZE_MISMATCH;
			}

			return ERROR_SUCCESS;
		}
	} while(ReadProcessMemory(hProcess, image.InLoadOrderModuleList.Flink, &image, sizeof(image), nullptr));

	return ERROR_NOT_FOUND;
}