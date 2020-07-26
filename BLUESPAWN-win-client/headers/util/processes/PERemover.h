#pragma once

#include <Windows.h>

#include <string>

#include "util/wrappers.hpp"
#include "util/dynamiclinker.h"

DEFINE_FUNCTION(NTSTATUS, NtResumeProcess, NTAPI, IN HANDLE ProcessHandle);

class PERemover {
	HandleWrapper hProcess;
	LPVOID lpBaseAddress;
	DWORD dwImageSize;
	
	bool AddressIsInRegion(LPVOID lpAddress);
	bool AdjustPointer(LPVOID lpAddress);

	bool CheckThreads();
	bool WalkThreadBack(const HandleWrapper& hThread, DWORD dwTID);
	bool AdjustPointers();
	bool WipeMemory();

public:
	PERemover(const HandleWrapper& hProcess, LPVOID lpBaseAddress, DWORD dwImageSize = -1);
	PERemover(DWORD dwPID, LPVOID lpBaseAddress, DWORD dwImageSize = -1);
	PERemover(const HandleWrapper& hProcess, const std::wstring& wsImageName);
	PERemover(DWORD dwPID, const std::wstring& wsImageName);

	bool RemoveImage();
};