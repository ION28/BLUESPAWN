#include <string>
#include <iostream>

#include "reactions/Log.h"
#include "logging/log.h"

namespace Reactions {
	void FileIdentified(FILE_DETECTION* detection){
		LOG_ERROR("File Identified: " << detection->wsFileName);
	}
	void RegistryKeyIdentified(REGISTRY_DETECTION* detection){
		LOG_ERROR("Registry Key Identified " << detection->wsRegistryKeyPath << ": " << detection->wsRegistryKeyValue);
	}
	void ProcessIdentified(PROCESS_DETECTION* detection){
		LOG_ERROR("Process " << detection->wsImageName << " Identified as malicious - PID " << detection->PID);
	}
	void ServiceIdentified(SERVICE_DETECTION* detection){
		LOG_ERROR(detection->wsServiceName << " was detected to be a malicious service!");
	}

	DetectFile FileHandler = &FileIdentified;
	DetectRegistry RegistryHandler = &RegistryKeyIdentified;
	DetectProcess ProcessHandler = &ProcessIdentified;
	DetectService ServiceHandler = &ServiceIdentified;

	Reactions::LogReaction::LogReaction(){
		vFileReactions.emplace_back(FileHandler);
		vRegistryReactions.emplace_back(RegistryHandler);
		vProcessReactions.emplace_back(ProcessHandler);
		vServiceReactions.emplace_back(ServiceHandler);
	}
}