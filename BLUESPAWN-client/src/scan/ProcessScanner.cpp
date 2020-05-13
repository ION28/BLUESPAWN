#include "scan/ProcessScanner.h"

#include "common/wrappers.hpp"
#include "util/filesystem/FileSystem.h"
#include "util/processes/ProcessUtils.h"
#include "util/configurations/Registry.h"
#include "hunt/Hunt.h"
#include "scan/YaraScanner.h"

#include "scan/FileScanner.h"
#include "scan/RegistryScanner.h"

std::map<ScanNode, Association> ProcessScanner::GetAssociatedDetections(const Detection& base, Aggressiveness level){
	if(!base || base->Type != DetectionType::Process){
		return {};
	}

	ProcessDetection detection = std::static_pointer_cast<PROCESS_DETECTION>(base);
	HandleWrapper hProcess{ OpenProcess(PROCESS_ALL_ACCESS, false, detection->PID) };
	std::map<ScanNode, Association> detections{};

	auto mapped{ GetMappedFile(hProcess, detection->lpAllocationBase) };
	if(mapped){
		detections.emplace(ScanNode(std::make_shared<FILE_DETECTION>(mapped->GetFilePath())), Association::Strong);
	}

	auto modules = EnumModules(hProcess);
	for(auto path : modules){
		if(FileSystem::CheckFileExists(path)){
			FileSystem::File file{ path };
			if(!file.GetFileSigned()){
				detections.emplace(ScanNode(std::make_shared<FILE_DETECTION>(path)), Association::Strong);
			}
			if(level > Aggressiveness::Cursory){
				auto& scanner{ YaraScanner::GetInstance() };
				if(scanner.ScanFile(file)){
					detections.emplace(ScanNode(std::make_shared<FILE_DETECTION>(path)), Association::Strong);
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
				detections.emplace(ScanNode(std::make_shared<FILE_DETECTION>(filename)), Association::Moderate);
			}

			auto keynames = RegistryScanner::ExtractRegistryKeys(strings);
			for(auto keyname : keynames){
				Registry::RegistryValue value{ Registry::RegistryKey{ keyname }, L"Unknown", std::move(std::wstring{ L"Unknown" }) };
				detections.emplace(ScanNode(std::make_shared<FILE_DETECTION>(value)), Association::Weak);
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
		}
		return { file };
	}
	return {};
}

Certainty ProcessScanner::ScanItem(const Detection& base, Aggressiveness level){
	return Certainty::None;
}