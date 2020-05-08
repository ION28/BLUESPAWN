#include "scan/ProcessScanner.h"

#include "common/wrappers.hpp"
#include "util/filesystem/FileSystem.h"
#include "util/processes/ProcessUtils.h"
#include "util/configurations/Registry.h"
#include "hunt/Hunt.h"
#include "scan/YaraScanner.h"

#include "scan/FileScanner.h"
#include "scan/RegistryScanner.h"

std::map<std::shared_ptr<ScanNode>, Association> ProcessScanner::GetAssociatedDetections(Detection base, Aggressiveness level){
	if(!base || base->Type != DetectionType::Process){
		return {};
	}

	ProcessDetection detection = std::static_pointer_cast<PROCESS_DETECTION>(base);
	HandleWrapper hProcess{ OpenProcess(PROCESS_ALL_ACCESS, false, detection->PID) };
	std::map<std::shared_ptr<ScanNode>, Association> detections{};

	auto mapped{ GetMappedFile(hProcess, detection->lpAllocationBase) };
	if(mapped){
		detections.emplace(std::make_shared<ScanNode>(std::make_shared<FILE_DETECTION>(mapped->GetFilePath())), Association::Strong);
	}

	auto modules = EnumModules(hProcess);
	for(auto path : modules){
		if(FileSystem::CheckFileExists(path)){
			FileSystem::File file{ path };
			if(!file.GetFileSigned()){
				detections.emplace(std::make_shared<ScanNode>(std::make_shared<FILE_DETECTION>(path)), Association::Strong);
			}
			if(level > Aggressiveness::Cursory){
				auto& scanner{ YaraScanner::GetInstance() };
				if(scanner.ScanFile(file)){
					detections.emplace(std::make_shared<ScanNode>(std::make_shared<FILE_DETECTION>(path)), Association::Strong);
				}
			}
		}
	}

	if(detection->lpAllocationBase && level > Aggressiveness::Cursory){
		auto memory{ Utils::Process::ReadProcessMemory(detection->PID, detection->lpAllocationBase, detection->dwAllocationSize) };
		if(memory){
			auto strings = FileScanner::ExtractStrings(memory, 8);
			auto filenames = FileScanner::ExtractFilePaths(strings);
			for(auto filename : filenames){
				detections.emplace(std::make_shared<ScanNode>(std::make_shared<FILE_DETECTION>(filename)), Association::Moderate);
			}

			auto keynames = RegistryScanner::ExtractRegistryKeys(strings);
			for(auto keyname : keynames){
				Registry::RegistryValue value{ Registry::RegistryKey{ keyname }, L"Unknown", std::move(std::wstring{ L"Unknown" }) };
				detections.emplace(std::make_shared<ScanNode>(std::make_shared<FILE_DETECTION>(value)), Association::Weak);
			}
		}
	}

	return detections;
}

Certainty ScanItem(const Detection& base, Aggressiveness level){
	return Certainty::None;
}