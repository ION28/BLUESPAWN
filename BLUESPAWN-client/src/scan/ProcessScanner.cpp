#include "scan/ProcessScanner.h"

#include "common/wrappers.hpp"
#include "util/filesystem/FileSystem.h"
#include "util/processes/ProcessUtils.h"
#include "hunt/Hunt.h"


std::vector<std::shared_ptr<DETECTION>> ProcessScanner::GetAssociatedDetections(std::shared_ptr<DETECTION> base, Aggressiveness level){
	if(!base || base->Type != DetectionType::Process){
		return {};
	}

	PROCESS_DETECTION detection = *std::static_pointer_cast<PROCESS_DETECTION>(base);
	HandleWrapper hProcess{ OpenProcess(PROCESS_ALL_ACCESS, false, detection.PID) };
	std::vector<std::shared_ptr<DETECTION>> detections{};

	auto modules = EnumModules(hProcess);
	for(auto path : modules){
		if(FileSystem::CheckFileExists(path)){
			FileSystem::File file{ path };
			if(!file.GetFileSigned()){
				FILE_DETECTION(file);
			}
		}
	}

	return detections;
}