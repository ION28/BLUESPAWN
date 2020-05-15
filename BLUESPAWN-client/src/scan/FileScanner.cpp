#include "scan/FileScanner.h"

#include <Psapi.h>

#include "common/wrappers.hpp"
#include "util/filesystem/FileSystem.h"
#include "util/processes/ProcessUtils.h"
#include "scan/RegistryScanner.h"
#include "scan/YaraScanner.h"
#include "scan/ScanNode.h"
#include "user/bluespawn.h"

#include <regex>

FILETIME FileScanner::lastupdate = { 0, 0 };
std::map<std::wstring, std::set<DWORD>> FileScanner::modules{};

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
	PWCHAR mem{ reinterpret_cast<PWCHAR>(LPVOID(data)) };
	for(DWORD idx = 0; 2 * idx < data.GetSize(); idx++){
		if(!(mem[idx] >= 0x20 && mem[idx] < 0x7E)){
			dwStringLength = idx - dwStringStart;
			if(dwStringLength >= dwMinLength){
				strings.emplace_back(std::wstring{ PWCHAR(LPVOID(data)) + dwStringStart, dwStringLength });
			}

			dwStringStart = idx + 1;
		}
	}

	dwStringLength = data.GetSize() / 2 - dwStringStart;
	if(dwStringLength >= dwMinLength && data.GetSize() / 2 > dwStringStart){
		strings.emplace_back(std::wstring{ mem + dwStringStart, dwStringLength });
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

void FileScanner::UpdateModules(){
	FILETIME time{};
	GetSystemTimeAsFileTime(&time);

	uint64_t tdiff{ (static_cast<uint64_t>(time.dwHighDateTime - lastupdate.dwHighDateTime) << 32) + time.dwLowDateTime - lastupdate.dwLowDateTime };
	DWORD dwSecondsElapsed = tdiff / 10000000;
	if(dwSecondsElapsed > 60){
		modules.clear();

		std::vector<DWORD> processes(1024);
		DWORD dwBytesNeeded{};
		auto success{ EnumProcesses(processes.data(), 1024 * sizeof(DWORD), &dwBytesNeeded) };
		if(dwBytesNeeded > 1024 * sizeof(DWORD)){
			processes.resize(dwBytesNeeded / sizeof(DWORD));
			success = EnumProcesses(processes.data(), dwBytesNeeded, &dwBytesNeeded);
		}

		auto dwProcCount{ dwBytesNeeded / sizeof(DWORD) };
		for(int i = 0; i < dwProcCount; i++){
			auto modules{ EnumModules(processes[i]) };
			for(auto& mod : modules){
				auto name{ ToLowerCaseW(mod) };
				if(FileScanner::modules.find(name) == FileScanner::modules.end()){
					FileScanner::modules.emplace(name, std::set<DWORD>{ processes[i] });
				} else FileScanner::modules.at(name).emplace(processes[i]);
			}
		}
	}
}

std::map<std::shared_ptr<ScanNode>, Association> FileScanner::GetAssociatedDetections(const std::shared_ptr<ScanNode>& node){
	if(!node->detection || node->detection->Type != DetectionType::File){
		return {};
	}
	std::map<std::shared_ptr<ScanNode>, Association> detections{};

	auto detection = *std::static_pointer_cast<FILE_DETECTION>(node->detection);
	auto ext = detection.wsFileName.substr(detection.wsFileName.size() - 4);
	if(ext != L".exe" && ext != L".dll"){
		return detections;
	}

	auto file{ FileSystem::File(detection.wsFilePath) };
	if(file.GetFileExists()){
		FileScanner::UpdateModules();

		auto contents{ file.Read() };
		auto path{ ToLowerCaseW(detection.wsFilePath) };

		for(auto mod : modules){
			if(Bluespawn::aggressiveness >= Aggressiveness::Cursory && mod.first == path){
				for(auto& pid : mod.second){
					auto alloc = GetModuleAddress(pid, mod.first);
					if(alloc){
						auto dwAllocSize = GetRegionSize(pid, alloc);
						auto detection{ std::make_shared<PROCESS_DETECTION>(GetProcessImage(pid), GetProcessCommandline(pid), pid, alloc,
																			dwAllocSize, static_cast<DWORD>(ProcessDetectionMethod::File)) };
						std::shared_ptr<ScanNode> associated{ std::make_shared<ScanNode>(detection) };
						associated->AddAssociation(node, Association::Certain);
						detections.emplace(associated, Association::Certain);
					}
				}
			} else if(Bluespawn::aggressiveness == Aggressiveness::Intensive && FileSystem::CheckFileExists(mod.first)){
				auto ModuleContents = FileSystem::File(mod.first).Read();
				if(contents.GetSize() == ModuleContents.GetSize() && contents.GetSize() == RtlCompareMemory(contents, ModuleContents, contents.GetSize())){
					for(auto& pid : mod.second){
						auto alloc = GetModuleAddress(pid, mod.first);
						if(alloc){
							auto dwAllocSize = GetRegionSize(pid, alloc);
							auto detection{ std::make_shared<PROCESS_DETECTION>(GetProcessImage(pid), GetProcessCommandline(pid), pid, alloc,
																				dwAllocSize, static_cast<DWORD>(ProcessDetectionMethod::File)) };
							std::shared_ptr<ScanNode> associated{ std::make_shared<ScanNode>(detection) };
							associated->AddAssociation(node, Association::Certain);
							detections.emplace(associated, Association::Certain);
						}
					}
				}
			}
		}

		auto strings = ExtractStrings(contents, 8);
		auto filenames = ExtractFilePaths(strings);
		for(auto& filename : filenames){
			std::shared_ptr<ScanNode> associated{ std::make_shared<ScanNode>(std::make_shared<FILE_DETECTION>(filename)) };
			associated->AddAssociation(node, Association::Moderate);
			detections.emplace(associated, Association::Moderate);
		}

		auto keynames = RegistryScanner::ExtractRegistryKeys(strings);
		for(auto keyname : keynames){
			Registry::RegistryValue value{ Registry::RegistryKey{ keyname }, L"Unknown", std::move(std::wstring{ L"Unknown" }) };
			std::shared_ptr<ScanNode> associated{ std::make_shared<ScanNode>(std::make_shared<REGISTRY_DETECTION>(value)) };
			associated->AddAssociation(node, Association::Weak);
			detections.emplace(associated, Association::Weak);
		}
	}

	return detections;
}

Certainty FileScanner::ScanItem(const std::shared_ptr<ScanNode>& detection){
	Certainty certainty{ Certainty::None };
	if(detection->detection->Type == DetectionType::File){
		auto& file{ std::static_pointer_cast<FILE_DETECTION>(detection->detection) };
		if(FileSystem::CheckFileExists(file->wsFilePath)){
			auto& f{ FileSystem::File(file->wsFilePath) };
			if(Bluespawn::aggressiveness >= Aggressiveness::Normal){
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
				certainty = AddAssociation(certainty, Certainty::Moderate);
			} else if(name.size() >= 5 && name.substr(name.size() - 5, 3) == L".ps"){
				certainty = AddAssociation(certainty, Certainty::Moderate);
			}
		}
	}

	detection->certainty = AddAssociation(detection->certainty, certainty);
	return certainty;
}