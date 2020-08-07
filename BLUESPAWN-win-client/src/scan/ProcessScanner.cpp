#include "scan/ProcessScanner.h"

#include <TlHelp32.h>

#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"
#include "util/processes/CheckLolbin.h"
#include "util/processes/ProcessUtils.h"
#include "util/wrappers.hpp"

#include "scan/FileScanner.h"
#include "user/bluespawn.h"

std::unordered_map<std::shared_ptr<Detection>, Association>
ProcessScanner::SearchCommand(IN CONST std::wstring& ProcessCommand) {
    // TODO: Better handling for parsing commands
    //LOG_ERROR(L"Unable to properly scan command `" << ProcessCommand << L"`; function not implemented");
    std::unordered_map<std::shared_ptr<Detection>, Association> detections{};

    auto image{ GetImagePathFromCommand(ProcessCommand) };
    if(FileScanner::PerformQuickScan(image)) {
        detections.emplace(Bluespawn::detections.AddDetection(Detection{ FileDetectionData{ image } }),
                           Association::Strong);
    }

    return detections;
}

std::unordered_map<std::shared_ptr<Detection>, Association>
ProcessScanner::GetAssociatedDetections(IN CONST Detection& detection) {
    if(detection.type != DetectionType::ProcessDetection) {
        return {};
    }

    std::unordered_map<std::shared_ptr<Detection>, Association> detections{};
    ProcessDetectionData data{ std::get<ProcessDetectionData>(detection.data) };

    if((data.type == ProcessDetectionType::MaliciousProcess || data.type == ProcessDetectionType::MaliciousCommand) &&
       data.ProcessCommand) {
        auto associated{ SearchCommand(*data.ProcessCommand) };
        for(auto& pair : associated) {
            detections.emplace(pair.first, pair.second);
        }
    }

    if(data.type == ProcessDetectionType::MaliciousProcess) {
        HandleWrapper snapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);

        if(Process32FirstW(snapshot, &entry)) {
            do {
                if(entry.th32ParentProcessID == data.PID) {
                    detections.emplace(
                        Bluespawn::detections.AddDetection(Detection{
                            ProcessDetectionData::CreateProcessDetectionData(entry.th32ProcessID, entry.szExeFile) }),
                        Association::Moderate);
                } else if(entry.th32ProcessID == data.PID) {
                    HandleWrapper parent{ OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false,
                                                      entry.th32ParentProcessID) };
                    if(parent) {
                        detections.emplace(Bluespawn::detections.AddDetection(
                                               Detection{ ProcessDetectionData::CreateProcessDetectionData(
                                                   entry.th32ParentProcessID, GetProcessImage(parent)) }),
                                           Association::Weak);
                    } else {
                        detections.emplace(
                            Bluespawn::detections.AddDetection(Detection{
                                ProcessDetectionData::CreateProcessDetectionData(entry.th32ParentProcessID, L"Unknow"
                                                                                                            L"n") }),
                            Association::Weak);
                    }
                }
            } while(Process32NextW(snapshot, &entry));
        }
    }

    return detections;
}

bool ProcessScanner::PerformQuickScan(IN CONST std::wstring& in) {
    // `in` is a command. Start by finding the associated executable
    auto file{ GetImagePathFromCommand(in) };

    // Check if the file appears malicious
    if(FileScanner::PerformQuickScan(file)) {
        return true;
    }

    // Check if the file appears to use a "lolbin" to obfuscate its execution
    bool lolbin{ IsLolbinMalicious(in) };

    return lolbin;
}

Certainty ProcessScanner::ScanDetection(IN CONST Detection& detection) {
    /// TODO: Implement check for LOLBins

    if(detection.type != DetectionType::ProcessDetection) {
        return Certainty::None;
    }

    ProcessDetectionData data{ std::get<ProcessDetectionData>(detection.data) };
    if(data.type == ProcessDetectionType::MaliciousProcess && data.ProcessCommand) {
        if(IsLolbinMalicious(*data.ProcessCommand)) {
            return Certainty::Moderate;
        }
    }

    return Certainty::None;
}
