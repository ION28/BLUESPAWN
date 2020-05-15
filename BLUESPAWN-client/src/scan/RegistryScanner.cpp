#include "scan/RegistryScanner.h"

#include "common/wrappers.hpp"
#include "util/configurations/Registry.h"
#include "util/processes/ProcessUtils.h"
#include "scan/YaraScanner.h"
#include "scan/ProcessScanner.h"
#include "user/bluespawn.h"

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

std::map<std::shared_ptr<ScanNode>, Association> RegistryScanner::GetAssociatedDetections(const std::shared_ptr<ScanNode>& node){
	if(!node->detection || node->detection->Type != DetectionType::Registry){
		return {};
	}
	std::map<std::shared_ptr<ScanNode>, Association> detections{};

	auto detection = std::static_pointer_cast<REGISTRY_DETECTION>(node->detection);
	if(detection){
		if(detection->type == RegistryDetectionType::CommandReference){
			if(detection->multitype){
				auto data{ std::get<std::vector<std::wstring>>(detection->value.data) };
				for(auto& entry : data){
					auto& files{ ProcessScanner::ScanCommand(entry) };
					for(auto& file : files){
						std::pair<std::shared_ptr<ScanNode>, Association> association{ std::make_shared<ScanNode>(std::make_shared<FILE_DETECTION>(file.GetFilePath())), Association::Certain };
						association.first->AddAssociation(node, association.second);
						detections.emplace(association);
					}
				}
			} else{
				auto& files{ ProcessScanner::ScanCommand(std::get<std::wstring>(detection->value.data)) };
				for(auto& file : files){
					std::pair<std::shared_ptr<ScanNode>, Association> association{ std::make_shared<ScanNode>(std::make_shared<FILE_DETECTION>(file.GetFilePath())), Association::Certain };
					association.first->AddAssociation(node, association.second);
					detections.emplace(association);
				}
			}
		}
		if(detection->type == RegistryDetectionType::FileReference){
			if(detection->multitype){
				auto data{ std::get<std::vector<std::wstring>>(detection->value.data) };
				for(auto& entry : data){
					auto file = FileSystem::SearchPathExecutable(entry);
					if(file){
						std::pair<std::shared_ptr<ScanNode>, Association> association{ std::make_shared<ScanNode>(std::make_shared<FILE_DETECTION>(*file)), Association::Certain };
						association.first->AddAssociation(node, association.second);
						detections.emplace(association);
					}
				}
			} else{
				auto file = FileSystem::SearchPathExecutable(std::get<std::wstring>(detection->value.data));
				if(file){
					std::pair<std::shared_ptr<ScanNode>, Association> association{ std::make_shared<ScanNode>(std::make_shared<FILE_DETECTION>(*file)), Association::Certain };
					association.first->AddAssociation(node, association.second);
					detections.emplace(association);
				}
			}
		} else if(detection->type == RegistryDetectionType::FolderReference){
			if(detection->multitype){
				auto data{ std::get<std::vector<std::wstring>>(detection->value.data) };
				for(auto& entry : data){
					std::pair<std::shared_ptr<ScanNode>, Association> association(std::make_shared<ScanNode>(std::make_shared<OTHER_DETECTION>(L"Folder",
																				  std::map<std::wstring, std::wstring>{
																					  { L"Path", entry }
					})), Association::Certain);
					association.first->AddAssociation(node, association.second);
					detections.emplace(association);
				}
			} else{
				std::pair<std::shared_ptr<ScanNode>, Association> association(std::make_shared<ScanNode>(std::make_shared<OTHER_DETECTION>(L"Folder",
																			  std::map<std::wstring, std::wstring>{
																				  { L"Path", std::get<std::wstring>(detection->value.data) }
				})), Association::Certain);
				association.first->AddAssociation(node, association.second);
				detections.emplace(association);
			}
		} else if(detection->type == RegistryDetectionType::UserReference){
			if(detection->multitype){
				auto data{ std::get<std::vector<std::wstring>>(detection->value.data) };
				for(auto& entry : data){
					std::pair<std::shared_ptr<ScanNode>, Association> association(std::make_shared<ScanNode>(std::make_shared<OTHER_DETECTION>(L"User",
																				  std::map<std::wstring, std::wstring>{
																					  { L"Identifier", entry }
					})), Association::Strong);
					association.first->AddAssociation(node, association.second);
					detections.emplace(association);
				}
			} else{
				std::pair<std::shared_ptr<ScanNode>, Association> association(std::make_shared<ScanNode>(std::make_shared<OTHER_DETECTION>(L"User",
																			  std::map<std::wstring, std::wstring>{
																				  { L"Identifier", std::get<std::wstring>(detection->value.data) }
				})), Association::Strong);
				association.first->AddAssociation(node, association.second);
				detections.emplace(association);
			}
		} else if(detection->type == RegistryDetectionType::PipeReference){
			if(detection->multitype){
				auto data{ std::get<std::vector<std::wstring>>(detection->value.data) };
				for(auto& entry : data){
					std::pair<std::shared_ptr<ScanNode>, Association> association(std::make_shared<ScanNode>(std::make_shared<OTHER_DETECTION>(L"Pipe",
																				  std::map<std::wstring, std::wstring>{
																					  { L"Identifier", entry }
					})), Association::Moderate);
					association.first->AddAssociation(node, association.second);
					detections.emplace(association);
				}
			} else{
				std::pair<std::shared_ptr<ScanNode>, Association> association(std::make_shared<ScanNode>(std::make_shared<OTHER_DETECTION>(L"Pipe",
																			  std::map<std::wstring, std::wstring>{
																				  { L"Identifier", std::get<std::wstring>(detection->value.data) }
				})), Association::Moderate);
				association.first->AddAssociation(node, association.second);
				detections.emplace(association);
			}
		} else if(detection->type == RegistryDetectionType::ShareReference){
			auto data{ std::get<std::vector<std::wstring>>(detection->value.data) };
			for(auto& entry : data){
				std::pair<std::shared_ptr<ScanNode>, Association> association(std::make_shared<ScanNode>(std::make_shared<OTHER_DETECTION>(L"Share",
																			  std::map<std::wstring, std::wstring>{
																				  { L"Name", entry }
				})), Association::Moderate);
				association.first->AddAssociation(node, association.second);
				detections.emplace(association);
			}
		} else{
			std::pair<std::shared_ptr<ScanNode>, Association> association(std::make_shared<ScanNode>(std::make_shared<OTHER_DETECTION>(L"Share",
																		  std::map<std::wstring, std::wstring>{
																			  { L"Name", std::get<std::wstring>(detection->value.data) }
			})), Association::Moderate);
			association.first->AddAssociation(node, association.second);
			detections.emplace(association);
		}
	}

	return detections;
}

Certainty RegistryScanner::ScanItem(const std::shared_ptr<ScanNode>& detection){
	if(Bluespawn::aggressiveness == Aggressiveness::Intensive && detection->detection->Type == DetectionType::Registry){
		auto reg{ std::static_pointer_cast<REGISTRY_DETECTION>(detection->detection) };
		if(reg){
			auto data{ reg->value.key.GetRawValue(reg->value.wValueName) };
			if(data.GetSize() > 0x10){
				auto& yara{ YaraScanner::GetInstance() };
				auto result{ yara.ScanMemory(data) };
				if(!result){
					if(result.vKnownBadRules.size() <= 1){
						detection->certainty = AddAssociation(detection->certainty, Certainty::Weak);
					} else if(result.vKnownBadRules.size() == 2){
						return detection->certainty = AddAssociation(detection->certainty, Certainty::Moderate);
					} else return detection->certainty = AddAssociation(detection->certainty, Certainty::Strong);
				}
			}
		}
	}

	return Certainty::None;
}