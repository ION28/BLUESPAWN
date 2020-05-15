#include "scan/ProcessScanner.h"

#include "common/wrappers.hpp"
#include "util/filesystem/FileSystem.h"
#include "util/processes/ProcessUtils.h"
#include "util/configurations/Registry.h"
#include "hunt/Hunt.h"
#include "user/bluespawn.h"

#include "scan/YaraScanner.h"
#include "scan/FileScanner.h"
#include "scan/RegistryScanner.h"

std::map<ScanNode, Association> ProcessScanner::GetAssociatedDetections(const ScanNode& node){
	if(!node.detection || node.detection->Type != DetectionType::Process){
		return {};
	}

	ProcessDetection detection = std::static_pointer_cast<PROCESS_DETECTION>(node.detection);
	HandleWrapper hProcess{ OpenProcess(PROCESS_ALL_ACCESS, false, detection->PID) };
	std::map<ScanNode, Association> detections{};

	auto mapped{ GetMappedFile(hProcess, detection->lpAllocationBase) };
	if(mapped){
		std::pair<ScanNode, Association> association(ScanNode(std::make_shared<FILE_DETECTION>(mapped->GetFilePath())), Association::Strong);
		association.first.AddAssociation(node, association.second);
		detections.emplace(association);
	}

	auto modules = EnumModules(hProcess);
	for(auto path : modules){
		if(FileSystem::CheckFileExists(path)){
			FileSystem::File file{ path };
			if(!file.GetFileSigned()){
				std::pair<ScanNode, Association> association(ScanNode(std::make_shared<FILE_DETECTION>(path)), Association::Strong);
				association.first.AddAssociation(node, association.second);
				detections.emplace(association);
			}
			if(Bluespawn::aggressiveness > Aggressiveness::Cursory){
				auto& scanner{ YaraScanner::GetInstance() };
				if(scanner.ScanFile(file)){
					std::pair<ScanNode, Association> association(ScanNode(std::make_shared<FILE_DETECTION>(path)), Association::Strong);
					association.first.AddAssociation(node, association.second);
					detections.emplace(association);
				}
			}
		}
	}

	if(detection->lpAllocationBase && Bluespawn::aggressiveness > Aggressiveness::Cursory){
		auto memory{ Utils::Process::ReadProcessMemory(detection->PID, detection->lpAllocationBase, detection->dwAllocationSize) };
		if(memory){
			auto strings = FileScanner::ExtractStrings(memory, 8);
			auto filenames = FileScanner::ExtractFilePaths(strings);
			for(auto filename : filenames){
				std::pair<ScanNode, Association> association(ScanNode(std::make_shared<FILE_DETECTION>(filename)), Association::Moderate);
				association.first.AddAssociation(node, association.second);
				detections.emplace(association);
			}

			auto keynames = RegistryScanner::ExtractRegistryKeys(strings);
			for(auto keyname : keynames){
				Registry::RegistryValue value{ Registry::RegistryKey{ keyname }, L"Unknown", std::move(std::wstring{ L"Unknown" }) };
				std::pair<ScanNode, Association> association(ScanNode(std::make_shared<REGISTRY_DETECTION>(value)), Association::Weak);
				association.first.AddAssociation(node, association.second);
				detections.emplace(association);
			}
		}
	}

	return detections;
}

std::vector<FileSystem::File> ProcessScanner::ScanCommand(const std::wstring& command){
	auto& executable{ GetImagePathFromCommand(command) };
	auto& file{ FileSystem::File(executable) };
	if(file.GetFileExists()){
		auto& mem{ file.Read() };
		if(mem.CompareMemory(FileSystem::File(L"cmd.exe").Read())){
			// Find the command
		} else if(mem.CompareMemory(FileSystem::File(L"powershell.exe").Read())){
			// Find the command
		} else if(mem.CompareMemory(FileSystem::File(L"rundll32.exe").Read())){
			// Find the dll
		} else if(mem.CompareMemory(FileSystem::File(L"dllhost.exe").Read())){
			// Find the dll
		} else if(mem.CompareMemory(FileSystem::File(L"explorer.exe").Read())){
			// Find LNK file
		} else if(mem.CompareMemory(FileSystem::File(L"RegSrv.exe").Read()))
		return { file };
	}
	return {};
}

Certainty ProcessScanner::ScanItem(ScanNode& base){
	return Certainty::None;
}