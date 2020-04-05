#include "scan/RegistryScanner.h"

#include "common/wrappers.hpp"
#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"
#include "hunt/Hunt.h"

#include <regex>

std::vector<std::wstring> ExtractRegistryKeys(const std::vector<std::wstring>& strings){
	std::vector<std::wstring> filepaths{};
	std::wregex regex{ L"[a-zA-Z]:([/\\\\][a-zA-Z0-9\\. @_-]+)+" };
	for(auto& string : strings){
		std::wsmatch match{};
		if(std::regex_search(string, match, regex)){
			for(auto& filename : match){
				if(FileSystem::CheckFileExists(filename)){
					filepaths.emplace_back(filename);
				}
			}
		}
	}
	return filepaths;
}

std::vector<std::shared_ptr<DETECTION>> RegistryScanner::GetAssociatedDetections(std::shared_ptr<DETECTION> base, Aggressiveness level){
	if(!base || base->Type != DetectionType::Registry){
		return {};
	}
	std::vector<std::shared_ptr<DETECTION>> detections{};

	auto detection = *std::static_pointer_cast<REGISTRY_DETECTION>(base);

	if(detection.type == RegistryDetectionType::FilesReference){
	}

	return detections;
}