#include "scan/RegistryScanner.h"

#include "util/wrappers.hpp"
#include "util/StringUtils.h"
#include "util/configurations/RegistryValue.h"
#include "util/processes/ProcessUtils.h"
#include "scan/YaraScanner.h"
#include "scan/ProcessScanner.h"
#include "scan/FileScanner.h"
#include "user/bluespawn.h"

#include <regex>

std::vector<std::wstring> RegistryScanner::ExtractRegistryKeys(IN CONST std::vector<std::wstring>& strings){
	std::vector<std::wstring> keys{};
	std::wregex regex{ L"(system|software)([/\\\\][a-zA-Z0-9\\. @_-]+)+" };
	for(auto& string : strings){
		std::wsmatch match{};
		auto lower{ ToLowerCaseW(string) };
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

std::unordered_map<std::shared_ptr<Detection>, Association> RegistryScanner::GetAssociatedDetections(
	IN CONST Detection& detection){
	if(detection.type != DetectionType::RegistryDetection || detection.DetectionStale){
		return {};
	}

	auto data{ std::get<RegistryDetectionData>(detection.data) };
	if(!data.key.Exists()){
		return {};
	}

	std::unordered_map<std::shared_ptr<Detection>, Association> detections{};

	if(!data.value){
		if(Bluespawn::aggressiveness == Aggressiveness::Intensive){
			for(auto val : data.key.EnumerateValues()){
				detections.emplace(Bluespawn::detections.AddDetection(Detection{
					RegistryDetectionData{ data.key, Registry::RegistryValue::Create(data.key, val) }
				}), Association::Moderate);
			}
		}

		return detections;
	} else if(!data.key.ValueExists(data.value->wValueName)){
		return {};
	}

	/// TODO: Add more of these
	if(data.type == RegistryDetectionType::CommandReference){
		if(ProcessScanner::PerformQuickScan(std::get<std::wstring>(data.value->data))){
			detections.emplace(Bluespawn::detections.AddDetection(Detection{
				ProcessDetectionData::CreateCommandDetectionData(std::get<std::wstring>(data.value->data))
			}), Association::Certain);
		}
	} else if(data.type == RegistryDetectionType::FileReference){
		auto name{ std::get<std::wstring>(data.value->data) };
		auto path{ FileSystem::SearchPathExecutable(name) };
		if(path && FileScanner::PerformQuickScan(*path)){
			detections.emplace(Bluespawn::detections.AddDetection(Detection{
				FileDetectionData{ *path }
			}), Association::Certain);
		}
	}

	return detections;
}

Certainty RegistryScanner::ScanDetection(IN CONST Detection& detection){
	if(Bluespawn::aggressiveness != Aggressiveness::Intensive || detection.type != DetectionType::RegistryDetection ||
	   detection.DetectionStale){
		
		return Certainty::None;
	}

	Certainty certainty{ Certainty::None };
	auto data{ std::get<RegistryDetectionData>(detection.data) };
	if(data.value){
		auto mem{ data.key.GetRawValue(data.value->wValueName) };
		if(mem.GetSize() > 0x10){
			auto result{ YaraScanner::GetInstance().ScanMemory(mem) };
			for(auto& rule : result.vKnownBadRules){
				// Tune this!
				certainty = certainty + Certainty::Moderate;
			}
		}
	}

	return certainty;
}