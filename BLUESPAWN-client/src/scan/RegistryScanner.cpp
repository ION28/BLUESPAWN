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

	if(detection.type == RegistryDetectionType::FilesReference && detection.value.GetType() == RegistryType::REG_MULTI_SZ_T){
		auto data{ std::get<std::vector<std::wstring>>(detection.value.data) };
		for(auto& entry : data){
			auto file = FileSystem::SearchPathExecutable(entry);
			if(file){
				FILE_DETECTION(*file);
			}
		}
	} else if(detection.type == RegistryDetectionType::FilesReference && (detection.value.GetType() == RegistryType::REG_SZ_T
		|| detection.value.GetType() == RegistryType::REG_EXPAND_SZ_T)){
		auto file = FileSystem::SearchPathExecutable(std::get<std::wstring>(detection.value.data));
		if(file){
			FILE_DETECTION(*file);
		}
	}

	return detections;
}