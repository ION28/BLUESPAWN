#include "scan/FileScanner.h"

#include <Psapi.h>

#include "common/wrappers.hpp"
#include "util/filesystem/FileSystem.h"
#include "util/processes/ProcessUtils.h"
#include "scan/RegistryScanner.h"
#include "scan/YaraScanner.h"
#include "scan/ScanNode.h"

#include <regex>

bool GetFilesSimilar(const AllocationWrapper& lpFile1, const AllocationWrapper& lpFile2){
	return lpFile1.GetSize() == lpFile2.GetSize() && lpFile1.GetSize() == RtlCompareMemory(lpFile1, lpFile2, lpFile1.GetSize());
}

std::vector<std::wstring> FileScanner::ExtractStrings(const AllocationWrapper& data, DWORD dwMinLength){
	std::vector<std::wstring> strings{};

	DWORD dwStringStart{};
	for(DWORD idx = 0; idx < data.GetSize(); idx++){
		if(!(data[idx] >= 0x20 && data[idx] < 0x7E)){
			DWORD dwStringLength = idx - dwStringStart;
			if(dwStringLength >= dwMinLength){
				strings.emplace_back(StringToWidestring(std::string{ PCHAR(LPVOID(data)) + dwStringStart, dwStringLength }));
			}

			dwStringStart = idx + 1;
		}
	}

	DWORD dwStringLength = data.GetSize() - dwStringStart;
	if(dwStringLength >= dwMinLength){
		strings.emplace_back(StringToWidestring(std::string{ PCHAR(LPVOID(data)) + dwStringStart, dwStringLength }));
	}

	dwStringStart = 0;
	for(DWORD idx = 0; 2 * idx < data.GetSize(); idx++){
		if(!(data[idx * 2] >= 0x20 && data[idx * 2] < 0x7E)){
			dwStringLength = idx - dwStringStart;
			if(dwStringLength >= dwMinLength){
				strings.emplace_back(std::wstring{ PWCHAR(LPVOID(data)) + dwStringStart, dwStringLength });
			}

			dwStringStart = idx + 1;
		}
	}

	dwStringLength = data.GetSize() - dwStringStart;
	if(dwStringLength >= dwMinLength){
		strings.emplace_back(std::wstring{ PWCHAR(PCHAR(LPVOID(data))) + dwStringStart, dwStringLength });
	}

	return strings;
}

std::vector<std::wstring> FileScanner::ExtractFilePaths(const std::vector<std::wstring>& strings){
	std::vector<std::wstring> filepaths{};
	std::wregex regex{ L"[a-zA-Z]:([/\\\\][a-zA-Z0-9\\. @_-]+)+" };
	for(auto& string : strings){
		std::wsmatch match{};
		if(std::regex_search(string, match, regex)){
			for(auto& filename : match){
				if(FileSystem::CheckFileExists(filename.str())){
					filepaths.emplace_back(filename.str());
				}
			}
		}
	}
	return filepaths;
}

std::map<ScanNode, Association> FileScanner::GetAssociatedDetections(const Detection& base, Aggressiveness level){
	if(!base || base->Type != DetectionType::File){
		return {};
	}
	std::map<ScanNode, Association> detections{};

	auto detection = *std::static_pointer_cast<FILE_DETECTION>(base);
	auto ext = detection.wsFileName.substr(detection.wsFileName.size() - 4);
	if(ext != L".exe" && ext != L".dll"){
		return detections;
	}

	auto file{ FileSystem::File(detection.wsFilePath) };
	auto contents{ file.Read() };

	std::vector<DWORD> processes(1024);
	DWORD dwBytesNeeded{};
	auto success{ EnumProcesses(processes.data(), 1024 * sizeof(DWORD), &dwBytesNeeded) };
	if(dwBytesNeeded > 1024 * sizeof(DWORD)){
		processes.resize(dwBytesNeeded / sizeof(DWORD));
		success = EnumProcesses(processes.data(), dwBytesNeeded, &dwBytesNeeded);
	}
	if(success){
		auto dwProcCount{ dwBytesNeeded / sizeof(DWORD) };
		for(int i = 0; i < dwProcCount; i++){
			auto modules{ EnumModules(processes[i]) };
			for(auto mod : modules){
				if(level >= Aggressiveness::Cursory && mod == detection.wsFilePath){
					auto alloc = GetModuleAddress(processes[i], mod);
					if(alloc){
						auto dwAllocSize = GetRegionSize(processes[i], alloc);
						auto detection{ std::make_shared<PROCESS_DETECTION>(GetProcessImage(processes[i]), GetProcessCommandline(processes[i]), processes[i], 
																			alloc, dwAllocSize, static_cast<DWORD>(ProcessDetectionMethod::File)) };
						detections.emplace(ScanNode(detection), Association::Certain);
					}
				} else if(level >= Aggressiveness::Normal && FileSystem::CheckFileExists(mod)){
					auto ModuleContents = FileSystem::File(mod).Read();
					if(contents.GetSize() == ModuleContents.GetSize() && contents.GetSize() == RtlCompareMemory(contents, ModuleContents, contents.GetSize())){
						auto alloc = GetModuleAddress(processes[i], mod);
						if(alloc){
							auto dwAllocSize = GetRegionSize(processes[i], alloc);
							auto detection{ std::make_shared<PROCESS_DETECTION>(GetProcessImage(processes[i]), GetProcessCommandline(processes[i]), processes[i],
																				alloc, dwAllocSize, static_cast<DWORD>(ProcessDetectionMethod::File)) };
							detections.emplace(ScanNode(detection), Association::Certain);
						}
						continue;
					}
				} else if(level == Aggressiveness::Intensive && FileSystem::CheckFileExists(mod)){
					auto ModuleContents = FileSystem::File(mod).Read();
					if(GetFilesSimilar(contents, ModuleContents)){
						auto alloc = GetModuleAddress(processes[i], mod);
						if(alloc){
							auto dwAllocSize = GetRegionSize(processes[i], alloc);
							auto detection{ std::make_shared<PROCESS_DETECTION>(GetProcessImage(processes[i]), GetProcessCommandline(processes[i]), processes[i],
																				alloc, dwAllocSize, static_cast<DWORD>(ProcessDetectionMethod::File)) };
							detections.emplace(ScanNode(detection), Association::Strong);
						}
					}
				}
			}
		}
	}

	auto strings = ExtractStrings(contents, 8);
	auto filenames = ExtractFilePaths(strings);
	for(auto& filename : filenames){
		detections.emplace(ScanNode(std::make_shared<FILE_DETECTION>(filename)), Association::Moderate);
	}

	auto keynames = RegistryScanner::ExtractRegistryKeys(strings);
	for(auto keyname : keynames){
		Registry::RegistryValue value{ Registry::RegistryKey{ keyname }, L"Unknown", std::move(std::wstring{ L"Unknown" }) };
		detections.emplace(ScanNode(std::make_shared<FILE_DETECTION>(value)), Association::Weak);
	}

	return detections;
}

Certainty FileScanner::ScanItem(const Detection& detection, Aggressiveness level){
	auto file{ std::static_pointer_cast<FILE_DETECTION>(detection) };
	Certainty certainty{ Certainty::None };
	if(file && FileSystem::CheckFileExists(file->wsFilePath)){
		auto& f{ FileSystem::File(file->wsFilePath) };
		if(level >= Aggressiveness::Normal){
			auto data{ f.Read() };
			if(data.GetSize() > 0x10){
				auto& yara{ YaraScanner::GetInstance() };
				auto result{ yara.ScanMemory(data) };
				if(!result){
					if(result.vKnownBadRules.size() <= 1){
						certainty = AddAssociation(certainty, Certainty::Weak);
					} else if(result.vKnownBadRules.size() == 2){
						certainty = AddAssociation(certainty, Certainty::Moderate);
					} else certainty = AddAssociation(certainty, Certainty::Strong);
				}
			}
		}

		auto& name{ file->wsFileName };
		if(name.size() >= 4 && (name.substr(name.size() - 4) == L".exe" || name.substr(name.size() - 4) == L".dll" || name.substr(name.size() - 4) == L".sys")){
			if(!f.GetFileSigned()){
				certainty = AddAssociation(certainty, Certainty::Strong);
			}
		}
		if(name.size() >= 4 && (name.substr(name.size() - 4, 3) == L".ps" || name.substr(name.size() - 4) == L".bat" || name.substr(name.size() - 4) == L".cmd")){
			if(!f.GetFileSigned()){
				certainty = AddAssociation(certainty, Certainty::Moderate);
			}
		}
	}

	return Certainty::None;
}