#include <string>
#include <iostream>

#include "reactions/Server.h"
#include "logging/log.h"

namespace Reactions {
	ServerReaction::ServerReaction() {
		dwSupportedReactions = IdentifyFile | IdentifyProcess | IdentifyRegistryKey | IdentifyService;
	}

	void ServerReaction::FileIdentified(HANDLE hFile) {
		char cFileName[256];
		bool success = GetFinalPathNameByHandleA(hFile, cFileName, 256, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
		if (success) {
			std::string sFileName(cFileName);
			LOG_ERROR("File Identified: " << sFileName);
		}
	}
	void ServerReaction::RegistryKeyIdentified(Registry::RegistryKey hkRegistryKey) {
		LOG_ERROR("NETWORK Registry Key Identified " << hkRegistryKey);
	}
	void ServerReaction::ProcessIdentified(HANDLE hProcess) {
		int pid = GetProcessId(hProcess);
		if (pid) {
			LOG_ERROR(std::string("Process Identified - PID ") << pid);
		}
	}
	void ServerReaction::ServiceIdentified(SC_HANDLE schService) {
		LOG_ERROR("A bad service was identified, but support for identifying which hasn't been added");
	}
}