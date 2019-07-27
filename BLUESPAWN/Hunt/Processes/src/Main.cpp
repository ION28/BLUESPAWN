#include <Windows.h>
#include <tlhelp32.h>

#include <iostream>

#include "processes/Analyzer.h"

int main(){
	PCWSTR ImageName = L"notepad.exe";

	CREATE_HANDLE(hProcessSnapshot, CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
	FAIL_IF_FALSE(hProcessSnapshot);

	PROCESSENTRY32 ProcessEntry{};
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32);

	FAIL_IF_FALSE(Process32First(hProcessSnapshot, &ProcessEntry));

	do if(wcscmp(ProcessEntry.szExeFile, ImageName)){
		CREATE_HANDLE(hProcess, OpenProcess(PROCESS_ALL_ACCESS, false, ProcessEntry.th32ProcessID));
		if(!hProcess){
			std::wcout << "Skipping " << ProcessEntry.szExeFile << " (PID " << ProcessEntry.th32ProcessID << ")" << std::endl;
			continue;
		}

		Analyzer analyzer{};
		std::wcout << ProcessEntry.szExeFile << " (PID " << ProcessEntry.th32ProcessID << ") passed checks: " << analyzer.ValidateProcess(hProcess) << std::endl;
	} while(Process32Next(hProcessSnapshot, &ProcessEntry));
}