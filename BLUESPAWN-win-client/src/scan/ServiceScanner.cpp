#include "scan/ServiceScanner.h"

#include <queue>

#include "util/StringUtils.h"

#include "scan/ProcessScanner.h"
#include "user/bluespawn.h"

std::unordered_map<std::shared_ptr<Detection>, Association>
ServiceScanner::GetAssociatedDetections(IN CONST Detection& detection) {
    if(detection.type != DetectionType::ServiceDetection) {
        return {};
    }

    std::unordered_map<std::shared_ptr<Detection>, Association> detections{};
    ServiceDetectionData data{ std::get<ServiceDetectionData>(detection.data) };

    if(data.FilePath) {
        detections.emplace(Bluespawn::detections.AddDetection(Detection{ FileDetectionData{ *data.FilePath } }),
                           Association::Certain);
    }

    if(!detection.DetectionStale) {
        std::wstring name{};
        if(!data.ServiceName && data.DisplayName) {
            GenericWrapper<SC_HANDLE> ServiceManager{ OpenSCManagerW(nullptr, nullptr, GENERIC_READ),
                                                      CloseServiceHandle };
            std::vector<WCHAR> KeyName(256);
            DWORD size{};
            if(!GetServiceKeyNameW(ServiceManager, data.DisplayName->c_str(), KeyName.data(), &size)) {
                KeyName.resize(size);
                if(GetServiceKeyNameW(ServiceManager, data.DisplayName->c_str(), KeyName.data(), &size)) {
                    name = KeyName.data();
                }
            } else {
                name = KeyName.data();
            }
        }

        if(name.length() || data.ServiceName) {
            if(data.ServiceName) {
                name = *data.ServiceName;
            }

            Registry::RegistryKey ServicesKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services" };

            std::queue<Registry::RegistryKey> bfsQueue{};
            bfsQueue.emplace(Registry::RegistryKey{ ServicesKey, name });
            std::set<Registry::RegistryKey> visited{};   // To avoid symlink loops
            while(!bfsQueue.empty()) {
                auto key{ bfsQueue.front() };
                bfsQueue.pop();

                if(visited.find(key) == visited.end()) {
                    visited.emplace(key);

                    for(auto name : key.EnumerateValues()) {
                        auto val{ Registry::RegistryValue::Create(key, name) };

                        // TODO: Add support for exes and dlls in REG_MULTI_SZ values
                        if(val && val->GetType() == RegistryType::REG_SZ_T ||
                           val->GetType() == RegistryType::REG_EXPAND_SZ_T) {
                            auto str{ ToLowerCaseW(std::get<std::wstring>(val->data)) };
                            if(str.find(L".exe") || str.find(L".dll")) {
                                detections.emplace(Bluespawn::detections.AddDetection(Detection{ RegistryDetectionData{
                                                       key, val, RegistryDetectionType::FileReference } }),
                                                   Association::Strong);
                            }
                        }
                    }

                    for(auto subkey : key.EnumerateSubkeys()) {
                        bfsQueue.emplace(subkey);
                    }
                }
            }
        }
    }

    return detections;
}

bool StringContainsKeywords(IN CONST std::wstring& str) {
    auto name{ ToLowerCaseW(str) };
    return name.find(L"psexecsvc") != std::wstring::npos || name.find(L"mimi") != std::wstring::npos;
}

bool ServiceScanner::PerformQuickScan(IN CONST std::optional<std::wstring>& ServiceName,
                                      IN CONST std::optional<std::wstring>& ServiceDisplayName,
                                      IN CONST std::optional<std::wstring>& ServicePath OPTIONAL) {
    if(ServicePath) {
        if(ProcessScanner::PerformQuickScan(*ServicePath)) {
            return true;
        }

        if(ServicePath->find(L"mimidrv.sys") != std::wstring::npos) {
            return true;
        }
    }

    if(ServiceName && StringContainsKeywords(*ServiceName)) {
        return true;
    }

    if(ServiceDisplayName && StringContainsKeywords(*ServiceDisplayName)) {
        return true;
    }

    return false;
}

Certainty ServiceScanner::ScanDetection(IN CONST Detection& detection) {
    if(detection.type == DetectionType::ServiceDetection) {
        ServiceDetectionData data{ std::get<ServiceDetectionData>(detection.data) };
        if(data.ServiceName && StringContainsKeywords(*data.ServiceName))
            return Certainty::Strong;
        if(data.DisplayName && StringContainsKeywords(*data.DisplayName))
            return Certainty::Strong;
        if(data.FilePath && StringContainsKeywords(*data.FilePath))
            return Certainty::Strong;
    }

    return Certainty::None;
}
