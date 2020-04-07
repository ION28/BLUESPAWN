#include "scan/FileScanner.h"

#include <Psapi.h>

#include "common/wrappers.hpp"
#include "util/filesystem/FileSystem.h"
#include "util/processes/ProcessUtils.h"
#include "hunt/Hunt.h"
#include "scan/RegistryScanner.h"

#include <regex>

bool GetFilesSimilar(const AllocationWrapper& lpFile1, const AllocationWrapper& lpFile2){
	return lpFile1.GetSize() == lpFile2.GetSize() && lpFile1.GetSize() == RtlCompareMemory(lpFile1, lpFile2, lpFile1.GetSize());
}

std::vector<std::wstring> FileScanner::ExtractStrings(const AllocationWrapper& data, DWORD dwMinLength){
	std::vector<std::wstring> strings{};

	DWORD dwStringStart{};
	for(DWORD idx = 0; idx < data.GetSize(); idx++){
		if(data[idx] >= 0x20 && data[idx] < 0x7E){
			
		} else {
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
		if(data[idx * 2] >= 0x20 && data[idx * 2] < 0x7E){

		} else {
			DWORD dwStringLength = idx - dwStringStart;
			if(dwStringLength >= dwMinLength){
				strings.emplace_back(std::wstring{ PWCHAR(LPVOID(data)) + dwStringStart, dwStringLength });
			}

			dwStringStart = idx + 1;
		}
	}

	DWORD dwStringLength = data.GetSize() - dwStringStart;
	if(dwStringLength >= dwMinLength){
		strings.emplace_back(StringToWidestring(std::string{ PCHAR(LPVOID(data)) + dwStringStart, dwStringLength }));
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

std::vector<std::shared_ptr<DETECTION>> FileScanner::GetAssociatedDetections(std::shared_ptr<DETECTION> base, Aggressiveness level){
	if(!base || base->Type != DetectionType::File){
		return {};
	}
	std::vector<std::shared_ptr<DETECTION>> detections{};

	auto detection = *std::static_pointer_cast<FILE_DETECTION>(base);
	auto ext = detection.wsFileName.substr(detection.wsFileName.size() - 4);
	if(ext != L".exe" && ext != L".dll"){
		return;
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
				if(level == Aggressiveness::Cursory){
					if(mod == detection.wsFilePath){
						PROCESS_DETECTION(GetProcessImage(processes[i]), GetProcessCommandline(processes[i]), processes[i], GetModuleAddress(processes[i], mod), -1, ProcessDetectionMethod::File);
					}
				} else if(level == Aggressiveness::Normal && FileSystem::CheckFileExists(mod)){
					auto ModuleContents = FileSystem::File(mod).Read();
					if(contents.GetSize() == ModuleContents.GetSize() && contents.GetSize() == RtlCompareMemory(contents, ModuleContents, contents.GetSize())){
						PROCESS_DETECTION(GetProcessImage(processes[i]), GetProcessCommandline(processes[i]), processes[i], GetModuleAddress(processes[i], mod), -1, ProcessDetectionMethod::File);
					}
				} else if(level == Aggressiveness::Intensive && FileSystem::CheckFileExists(mod)){
					auto ModuleContents = FileSystem::File(mod).Read();
					if(GetFilesSimilar(contents, ModuleContents)){
						PROCESS_DETECTION(GetProcessImage(processes[i]), GetProcessCommandline(processes[i]), processes[i], GetModuleAddress(processes[i], mod), -1, ProcessDetectionMethod::File);
					}
				}
			}
		}
	}

	auto strings = ExtractStrings(contents, 8);
	auto filenames = ExtractFilePaths(strings);
	for(auto& filename : filenames){
		FILE_DETECTION(filename);
	}

	auto keynames = RegistryScanner::ExtractRegistryKeys(strings);
	for(auto keyname : keynames){
		Registry::RegistryValue value{ Registry::RegistryKey{ keyname }, L"Unknown", std::move(std::wstring{ L"Unknown" }) };
		REGISTRY_DETECTION(value);
	}

	return detections;
}