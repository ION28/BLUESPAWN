#include "scan/RegistryScanner.h"

#include "common/wrappers.hpp"
#include "util/configurations/Registry.h"
#include "util/processes/ProcessUtils.h"
#include "scan/YaraScanner.h"
#include "scan/ProcessScanner.h"

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

std::map<ScanNode, Association> RegistryScanner::GetAssociatedDetections(const Detection& base, Aggressiveness level){
	if(!base || base->Type != DetectionType::Registry){
		return {};
	}
	std::map<ScanNode, Association> detections{};

	auto detection = std::static_pointer_cast<REGISTRY_DETECTION>(base);
	if(detection){
		if(detection->type == RegistryDetectionType::CommandReference){
			if(detection->multitype){
				auto data{ std::get<std::vector<std::wstring>>(detection->value.data) };
				for(auto& entry : data){
					auto& files{ ProcessScanner::ScanCommand(entry) };
					for(auto& file : files){
						detections.emplace(ScanNode(std::make_shared<FILE_DETECTION>(file)), Association::Certain);
					}
				}
			} else{
				auto& files{ ProcessScanner::ScanCommand(std::get<std::wstring>(detection->value.data)) };
				for(auto& file : files){
					detections.emplace(ScanNode(std::make_shared<FILE_DETECTION>(file)), Association::Certain);
				}
			}
		}
		if(detection->type == RegistryDetectionType::FileReference){
			if(detection->multitype){
				auto data{ std::get<std::vector<std::wstring>>(detection->value.data) };
				for(auto& entry : data){
					auto file = FileSystem::SearchPathExecutable(entry);
					if(file){
						detections.emplace(ScanNode(std::make_shared<FILE_DETECTION>(*file)), Association::Certain);
					}
				}
			} else{
				auto file = FileSystem::SearchPathExecutable(std::get<std::wstring>(detection->value.data));
				if(file){
					detections.emplace(ScanNode(std::make_shared<FILE_DETECTION>(*file)), Association::Certain);
				}
			}
		} else if(detection->type == RegistryDetectionType::FolderReference){
			if(detection->multitype){
				auto data{ std::get<std::vector<std::wstring>>(detection->value.data) };
				for(auto& entry : data){
					detections.emplace(ScanNode(std::make_shared<OTHER_DETECTION>(L"Folder",
																				  std::unordered_map<std::wstring, std::wstring>{
																					  { L"Path", entry }
					})));
				}
			} else{
				detections.emplace(ScanNode(std::make_shared<OTHER_DETECTION>(L"Folder",
																			  std::unordered_map<std::wstring, std::wstring>{
																				  { L"Path", std::get<std::wstring>(detection->value.data) }
				})), Association::Certain);
			}
		} else if(detection->type == RegistryDetectionType::UserReference){
			if(detection->multitype){
				auto data{ std::get<std::vector<std::wstring>>(detection->value.data) };
				for(auto& entry : data){
					detections.emplace(ScanNode(std::make_shared<OTHER_DETECTION>(L"User",
																				  std::unordered_map<std::wstring, std::wstring>{
																					  { L"Identifier", entry }
					})), Association::Strong);
				}
			} else{
				detections.emplace(ScanNode(std::make_shared<OTHER_DETECTION>(L"User",
																			  std::unordered_map<std::wstring, std::wstring>{
																				  { L"Identifier", std::get<std::wstring>(detection->value.data) }
				})), Association::Strong);
			}
		} else if(detection->type == RegistryDetectionType::PipeReference){
			if(detection->multitype){
				auto data{ std::get<std::vector<std::wstring>>(detection->value.data) };
				for(auto& entry : data){
					detections.emplace(ScanNode(std::make_shared<OTHER_DETECTION>(L"Pipe",
																				  std::unordered_map<std::wstring, std::wstring>{
																					  { L"Identifier", entry }
					})), Association::Moderate);
				}
			} else{
				detections.emplace(ScanNode(std::make_shared<OTHER_DETECTION>(L"Pipe",
																			  std::unordered_map<std::wstring, std::wstring>{
																				  { L"Identifier", std::get<std::wstring>(detection->value.data) }
				})), Association::Moderate);
			}
		} else if(detection->type == RegistryDetectionType::ShareReference){
			auto data{ std::get<std::vector<std::wstring>>(detection->value.data) };
			for(auto& entry : data){
				detections.emplace(ScanNode(std::make_shared<OTHER_DETECTION>(L"Share",
																			  std::unordered_map<std::wstring, std::wstring>{
																				  { L"Name", entry }
				})), Association::Moderate);
			}
		} else{
			detections.emplace(ScanNode(std::make_shared<OTHER_DETECTION>(L"Share",
																		  std::unordered_map<std::wstring, std::wstring>{
																			  { L"Name", std::get<std::wstring>(detection->value.data) }
			})), Association::Moderate);
		}
	}

	return detections;
}

Certainty RegistryScanner::ScanItem(const Detection& detection, Aggressiveness level){
	if(level == Aggressiveness::Intensive){
		auto reg{ std::static_pointer_cast<REGISTRY_DETECTION>(detection) };
		if(reg){
			auto data{ reg->value.key.GetRawValue(reg->value.wValueName) };
			if(data.GetSize() > 0x10){
				auto& yara{ YaraScanner::GetInstance() };
				auto result{ yara.ScanMemory(data) };
				if(!result){
					if(result.vKnownBadRules.size() <= 1){
						return Certainty::Weak;
					} else if(result.vKnownBadRules.size() == 2){
						return Certainty::Moderate;
					} else return Certainty::Strong;
				}
			}
		}
	}

	return Certainty::None;
}