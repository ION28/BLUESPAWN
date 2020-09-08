#include "scan/FileScanner.h"

#include <Psapi.h>

#include <regex>

#include "util/StringUtils.h"
#include "util/wrappers.hpp"

#include "util/filesystem/FileSystem.h"
#include "util/processes/ProcessUtils.h"

#include "scan/ProcessScanner.h"
#include "scan/RegistryScanner.h"
#include "scan/ScanInfo.h"
#include "scan/YaraScanner.h"
#include "user/bluespawn.h"

bool GetFilesSimilar(const AllocationWrapper& lpFile1, const AllocationWrapper& lpFile2) {
    return lpFile1.GetSize() == lpFile2.GetSize() &&
           lpFile1.GetSize() == RtlCompareMemory(lpFile1, lpFile2, lpFile1.GetSize());
}

std::vector<std::wstring> FileScanner::ExtractStrings(IN CONST AllocationWrapper& data, IN DWORD dwMinLength OPTIONAL) {
    std::vector<std::wstring> strings{};

    DWORD dwStringStart{};
    for(DWORD idx = 0; idx < data.GetSize(); idx++) {
        if(!(data[idx] >= 0x20 && data[idx] <= 0x7F)) {
            DWORD dwStringLength = idx - dwStringStart;
            if(dwStringLength >= dwMinLength) {
                strings.emplace_back(
                    StringToWidestring(std::string{ PCHAR(LPVOID(data)) + dwStringStart, dwStringLength }));
            }

            dwStringStart = idx + 1;
        }
    }

    auto dwStringLength = data.GetSize() - dwStringStart;
    if(dwStringLength >= dwMinLength) {
        strings.emplace_back(StringToWidestring(std::string{ PCHAR(LPVOID(data)) + dwStringStart, dwStringLength }));
    }

    dwStringStart = 0;
    auto mem{ reinterpret_cast<PWCHAR>(LPVOID(data)) };
    for(DWORD idx = 0; 2 * idx < data.GetSize(); idx++) {
        if(!(mem[idx] >= 0x20 && mem[idx] < 0x7E)) {
            dwStringLength = idx - dwStringStart;
            if(dwStringLength >= dwMinLength) {
                strings.emplace_back(std::wstring{ PWCHAR(LPVOID(data)) + dwStringStart, dwStringLength });
            }

            dwStringStart = idx + 1;
        }
    }

    dwStringLength = data.GetSize() / 2 - dwStringStart;
    if(dwStringLength >= dwMinLength && data.GetSize() / 2 > dwStringStart) {
        strings.emplace_back(std::wstring{ mem + dwStringStart, dwStringLength });
    }

    return strings;
}

std::vector<std::wstring> FileScanner::ExtractFilePaths(IN CONST std::vector<std::wstring>& strings) {
    std::vector<std::wstring> filepaths{};
    std::wregex regex{ L"[a-zA-Z]:([/\\\\][a-zA-Z0-9(). @_-]+)+" };
    for(auto& string : strings) {
        std::wsmatch match{};
        if(std::regex_search(string, match, regex)) {
            for(auto& filename : match) {
                if(FileSystem::CheckFileExists(filename.str())) {
                    filepaths.emplace_back(filename.str());
                }
            }
        }
    }
    return filepaths;
}

void FileScanner::UpdateModules() {
    BeginCriticalSection _{ hGuard };

    FILETIME time{};
    GetSystemTimeAsFileTime(&time);

    uint64_t tdiff{ (static_cast<uint64_t>(time.dwHighDateTime - ModuleLastUpdateTime.dwHighDateTime) << 32) +
                    time.dwLowDateTime - ModuleLastUpdateTime.dwLowDateTime };
    DWORD dwSecondsElapsed = tdiff / 10000;
    if(dwSecondsElapsed >= MODULE_UPDATE_INTERVAL) {
        modules.clear();
        hashes.clear();

        std::vector<DWORD> processes(1024);
        DWORD dwBytesNeeded{};
        auto success{ EnumProcesses(processes.data(), 1024 * sizeof(DWORD), &dwBytesNeeded) };
        if(dwBytesNeeded > 1024 * sizeof(DWORD)) {
            processes.resize(dwBytesNeeded / sizeof(DWORD));
            success = EnumProcesses(processes.data(), dwBytesNeeded, &dwBytesNeeded);
        }

        auto dwProcCount{ dwBytesNeeded / sizeof(DWORD) };
        for(int i = 0; i < dwProcCount; i++) {
            auto modules{ EnumModules(processes[i]) };
            for(auto& mod : modules) {
                auto name{ ToLowerCaseW(mod) };
                if(FileScanner::modules.find(name) == FileScanner::modules.end()) {
                    FileScanner::modules.emplace(name, std::unordered_set<DWORD>{ processes[i] });
                } else {
                    FileScanner::modules.at(name).emplace(processes[i]);
                }
            }
        }

        for(auto& mod : modules) {
            auto path{ FileSystem::SearchPathExecutable(mod.first) };
            if(path) {
                auto hash{ FileSystem::File{ *path }.GetSHA256Hash() };
                if(hash) {
                    if(hashes.count(*hash)) {
                        hashes.at(*hash).emplace(mod.first);
                    } else {
                        hashes.emplace(*hash, std::unordered_set<std::wstring>{ mod.first });
                    }
                }
            }
        }

        ModuleLastUpdateTime = time;
    }
}

bool IsPEFile(IN CONST FileSystem::File& file){
    if(file.GetFileExists()){
        if(!file.HasReadAccess()){
            LOG_WARNING(L"Unable to properly scan " << file << L" due to lack of read access.");
            return false;
        }

        auto headers{ file.Read(0x400) };
        MemoryWrapper<> memory{ static_cast<LPVOID>(headers), headers.GetSize() };
        if(*memory.Convert<WORD>() != 0x5A4D){
            return false;
        }

        DWORD offset{ *memory.GetOffset(0x3C).Convert<DWORD>() };
        if(offset + 4 >= 0x400){
            LOG_INFO(2, "File " << file << " may conform to the PE32+ standard, but it is not normal PE.");
            return false;
        }

        return *memory.GetOffset(offset).Convert<DWORD>() == 0x4550UL;
    } else{
        return false;
    }
}

bool FileScanner::PerformQuickScan(IN CONST std::wstring& string) {
    if(FileSystem::CheckFileExists(string)) {
        return !FileSystem::File{ string }.GetFileSigned();
    } else if(auto path{ FileSystem::SearchPathExecutable(string) }){
        return !FileSystem::File{ *path }.GetFileSigned();
    } else{
        return false;
    }
}

std::unordered_map<std::shared_ptr<Detection>, Association>
FileScanner::GetAssociatedDetections(IN CONST Detection& detection) {
    if(detection.type != DetectionType::FileDetection || detection.info.certainty < Certainty::Moderate) {
        return {};
    }

    std::unordered_map<std::shared_ptr<Detection>, Association> detections{};

    auto data{ std::get<FileDetectionData>(detection.data) };

    if(data.Executor && !IsPEFile(*data.FileHandle) && ProcessScanner::PerformQuickScan(*data.Executor)) {
        detections.emplace(Bluespawn::detections.AddDetection(
            Detection{ ProcessDetectionData::CreateCommandDetectionData(*data.Executor) }), Association::Strong);
    }

    if(data.FileFound) {
        UpdateModules();

        EnterCriticalSection(hGuard);
        auto hashes{ this->hashes };
        auto modules{ this->modules };
        LeaveCriticalSection(hGuard);

        if(data.SHA256) {
            if(hashes.count(*data.SHA256)) {
                auto loaded{ hashes.at(*data.SHA256) };
                for(auto& lib : loaded) {
                    for(auto pid : modules.at(lib)) {
                        auto alloc{ GetModuleAddress(pid, lib) };
                        if(alloc) {
                            auto dwAllocSize{ GetRegionSize(pid, alloc) };
                            detections.emplace(
                                Bluespawn::detections.AddDetection(Detection{
                                    ProcessDetectionData::CreateImageDetectionData(pid, GetProcessImage(pid), lib) }),
                                Association::Certain);
                        }
                    }
                }
            }
        }

        if(!detection.DetectionStale && data.FileHandle && Bluespawn::aggressiveness == Aggressiveness::Intensive) {
            auto strings = ExtractStrings(data.FileHandle->Read(), 8);
            auto filenames = ExtractFilePaths(strings);
            for(auto& filename : filenames) {
                if(FileScanner::PerformQuickScan(filename)){
                    detections.emplace(Bluespawn::detections.AddDetection(Detection{ FileDetectionData{ filename } }),
                                       Association::Weak);
                }
            }
        }
    }

    return detections;
}

Certainty FileScanner::ScanDetection(IN CONST Detection& detection) {
    Certainty certainty{ Certainty::None };
    if(detection.type == DetectionType::FileDetection) {
        auto& file{ std::get<FileDetectionData>(detection.data) };
        if(!file.FileFound) {
            return Certainty::None;
        }

        if(IsPEFile(*file.FileHandle)){
            if(file.FileHandle->IsMicrosoftSigned()){
                return Certainty::None;
            }
            if(!*file.FileSigned){
                certainty = certainty + Certainty::Moderate;
            }
            if(file.yara){
                for(auto& rule : file.yara->vKnownBadRules){
                    // Tune this!
                    certainty = certainty + Certainty::Moderate;
                }
            }
        } else{
            if(file.Executor){
                if(ProcessScanner::PerformQuickScan(*file.Executor)){
                    certainty = certainty + Certainty::Moderate;
                }
            }
        }

        LOG_INFO(2, L"Scanned file " << file.FilePath << ". Certainty: " << static_cast<double>(certainty));
    }
    return certainty;
}
