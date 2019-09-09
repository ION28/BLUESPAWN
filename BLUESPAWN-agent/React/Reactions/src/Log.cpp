#include <string>
#include <iostream>

#include "reactions/Log.h"
#include "logging/log.h"

namespace Reactions {
	LogReaction::LogReaction(){
		dwSupportedReactions = IdentifyFile | IdentifyProcess | IdentifyRegistryKey | IdentifyService;
	}

	void LogReaction::FileIdentified(HANDLE hFile){
		char cFileName[256];
		bool success = GetFinalPathNameByHandleA(hFile, cFileName, 256, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
		if(success){
			std::string sFileName(cFileName);
			LOG_ERROR("File Identified: " << sFileName);
		}
	}
	void LogReaction::RegistryKeyIdentified(Registry::RegistryKey hkRegistryKey){
		LOG_ERROR("Registry Key Identified " << hkRegistryKey);
	}
	void LogReaction::ProcessIdentified(HANDLE hProcess){
		int pid = GetProcessId(hProcess);
		if(pid){
			LOG_ERROR(std::string("Process Identified - PID ") << pid);
		}
	}
	void LogReaction::ServiceIdentified(SC_HANDLE schService){
		LOG_ERROR("A bad service was identified, but support for identifying which hasn't been added");
	}
}