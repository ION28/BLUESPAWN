#include "scan/ProcessScanner.h"

#include "common/wrappers.hpp"
#include "util/filesystem/FileSystem.h"
#include "util/processes/ProcessUtils.h"
#include "util/configurations/Registry.h"
#include "hunt/Hunt.h"

#include "scan/FileScanner.h"
#include "scan/RegistryScanner.h"

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
				FILE_DETECTION(path);
			}
		}
	}

	if(detection.lpAllocationBase){
		auto memory{ Utils::Process::ReadProcessMemory(detection.PID, detection.lpAllocationBase, detection.dwAllocationSize) };
		if(memory){
			auto strings = FileScanner::ExtractStrings(memory, 8);
			auto filenames = FileScanner::ExtractFilePaths(strings);
			for(auto filename : filenames){
				FILE_DETECTION(filename);
			}

			auto keynames = RegistryScanner::ExtractRegistryKeys(strings);
			for(auto keyname : keynames){
				Registry::RegistryValue value{ Registry::RegistryKey{ keyname }, L"Unknown", std::move(std::wstring{ L"Unknown" }) };
				REGISTRY_DETECTION(value);
			}
		}
	}

	return detections;
}