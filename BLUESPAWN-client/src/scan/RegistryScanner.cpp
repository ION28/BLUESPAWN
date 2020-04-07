#include "scan/RegistryScanner.h"

#include "common/wrappers.hpp"
#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"
#include "hunt/Hunt.h"

#include <regex>

std::vector<std::wstring> RegistryScanner::ExtractRegistryKeys(const std::vector<std::wstring>& strings){
	std::vector<std::wstring> keys{};
	std::wregex regex{ L"(system|software)([/\\\\][a-zA-Z0-9\\. @_-]+)+" };
	for(auto& string : strings){
		std::wsmatch match{};
		auto lower = ToLowerCaseW(string);
		if(std::regex_search(lower, match, regex)){
			for(auto& keyname : match){
				for(auto hive : Registry::vHives){
					if(Registry::RegistryKey::CheckKeyExists(hive.first, keyname.str())){
						keys.emplace_back(hive.second + L"\\" + keyname.str());
					}
				}
			}
		}
	}
	return keys;
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