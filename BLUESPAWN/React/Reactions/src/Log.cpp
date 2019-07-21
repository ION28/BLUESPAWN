#include <string>
#include <iostream>
#include "Log.h"
#include "Output.h"

namespace Reactions {
	Log::Log(){
		dwSupportedReactions = IdentifyFile | IdentifyProcess | IdentifyRegistryKey | IdentifyService;
	}

	void Log::FileIdentified(HANDLE hFile){
		char cFileName[256];
		bool success = GetFinalPathNameByHandleA(hFile, cFileName, 256, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
		if(success){
			std::string sFileName(cFileName);
			PrintBadStatus(std::string("File Identified: ") + sFileName);
		}
	}
	void Log::RegistryKeyIdentified(HKEY hkRegistryKey){
		PrintBadStatus("A bad registry key was identified, but support for identifying which hasn't been added");
	}
	void Log::ProcessIdentified(HANDLE hProcess){
		int pid = GetProcessId(hProcess);
		if(pid){
			PrintBadStatus(std::string("Process Identified: ") + to_string(pid));
		}
	}
	void Log::ServiceIdentified(SC_HANDLE schService){
		PrintBadStatus("A bad service was identified, but support for identifying which hasn't been added");
	}
}