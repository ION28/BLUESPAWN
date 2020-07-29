#include "hunt/hunts/HuntT1547.h"

#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"

#include "hunt/RegistryHunt.h"
#include "scan/FileScanner.h"
#include "scan/ProcessScanner.h"
#include "user/bluespawn.h"

using namespace Registry;

namespace Hunts {

    HuntT1547::HuntT1547() : Hunt(L"T1547 - Boot or Logon Autostart Execution") {
        dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
        dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
        dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;

        auto HKLMRun = std::wstring{ L"Software\\Microsoft\\Windows\\CurrentVersion\\Run" };
        auto HKLMRunServices = std::wstring{ L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" };
        auto HKLMRunOnce = std::wstring{ L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" };
        auto HKLMRunServicesOnce = std::wstring{ L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceServices" };
        auto HKLMRunOnceEx = std::wstring{ L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx" };
        auto HKLMRunServicesOnceEx = std::wstring{ L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceServicesEx" };
        auto HKLMExplorerRun = std::wstring{ L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" };

        RunKeys = {
            HKLMRun,       HKLMRunServices,       HKLMRunOnce,     HKLMRunServicesOnce,
            HKLMRunOnceEx, HKLMRunServicesOnceEx, HKLMExplorerRun,
        };
    }

    std::vector<std::shared_ptr<Detection>> HuntT1547::RunHunt(const Scope& scope) {
        HUNT_INIT();

        // Looks for T1547.001: Registry Run Keys / Startup Folder
        for(auto& key : RunKeys) {
            for(auto& detection : CheckKeyValues(HKEY_LOCAL_MACHINE, key)) {
                if(ProcessScanner::PerformQuickScan(std::get<std::wstring>(detection.data))) {
                    CREATE_DETECTION_WITH_CONTEXT(Certainty::Moderate,
                                                  RegistryDetectionData{ detection,
                                                                         RegistryDetectionType::CommandReference },
                                                  DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1547_001) });
                }
            }
        }

        for(auto& detection : CheckValues(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Command Processor",
                                          { { L"AutoRun", L"", false, CheckSzEmpty } })) {
            CREATE_DETECTION_WITH_CONTEXT(Certainty::Strong,
                                          RegistryDetectionData{ detection, RegistryDetectionType::CommandReference },
                                          DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1547_001) });
        }

        for(auto& detection : CheckValues(
                HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
                { { L"Startup", L"%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                    false, CheckSzEqual } })) {
            CREATE_DETECTION_WITH_CONTEXT(Certainty::Moderate,
                                          RegistryDetectionData{ detection, RegistryDetectionType::FolderReference },
                                          DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1547_001) });
        }

        for(auto& detection :
            CheckValues(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
                        { { L"Common Startup", L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                            false, CheckSzEqual } })) {
            CREATE_DETECTION_WITH_CONTEXT(Certainty::Moderate,
                                          RegistryDetectionData{ detection, RegistryDetectionType::FolderReference },
                                          DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1547_001) });
        }

        // Looks for T1547.002: Authentication Package
        // LSA Configuration
        auto lsa = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" };
        for(auto PackageGroup : { L"Authentication Packages", L"Notification Packages" }) {
            auto packages = lsa.GetValue<std::vector<std::wstring>>(PackageGroup);
            if(packages) {
                for(auto package : *packages) {
                    auto filepath = FileSystem::SearchPathExecutable(package + L".dll");

                    if(filepath && FileScanner::PerformQuickScan(*filepath)) {
                        // Can't use a macro since we need the shared_ptr of the detection
                        auto value{ Bluespawn::detections.AddDetection(
                            Detection{ RegistryDetectionData{ RegistryValue{ lsa, PackageGroup, std::move(package) },
                                                              RegistryDetectionType::FileReference },
                                       DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1547_002) } },
                            Certainty::Moderate) };
                        detections.emplace_back(value);

                        // Since the security package is missing the dll extension, the scanner may not find the
                        // associated file
                        auto file{ Bluespawn::detections.AddDetection(
                            Detection{ FileDetectionData{ *filepath },
                                       DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1547_002) } },
                            Certainty::Weak) };
                        detections.emplace_back(file);

                        // Define the association here since the scanner may not pick up on it
                        file->info.AddAssociation(value, Association::Certain);
                        value->info.AddAssociation(file, Association::Certain);
                    }
                }
            }
        }

        // LSA Extensions Configuration
        auto lsaext = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\LsaExtensionConfig" };
        for(auto subkeyName : lsaext.EnumerateSubkeyNames()) {
            if(subkeyName == L"Interfaces") {
                for(auto subkey : RegistryKey{ lsaext, L"Interfaces" }.EnumerateSubkeys()) {
                    auto ext{ RegistryValue::Create(subkey, L"Extension") };
                    if(ext && FileScanner::PerformQuickScan(ext->ToString())) {
                        CREATE_DETECTION_WITH_CONTEXT(
                            Certainty::Moderate, RegistryDetectionData{ *ext, RegistryDetectionType::FileReference },
                            DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1547_002) });
                    }
                }
            } else {
                auto subkey = RegistryKey{ lsaext, subkeyName };
                auto exts = subkey.GetValue<std::vector<std::wstring>>(L"Extensions");
                if(exts) {
                    for(auto ext : *exts) {
                        if(FileScanner::PerformQuickScan(ext)) {
                            CREATE_DETECTION_WITH_CONTEXT(
                                Certainty::Moderate,
                                RegistryDetectionData{ RegistryValue{ subkey, L"Extensions", std::move(ext) },
                                                       RegistryDetectionType::FileReference },
                                DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1547_002) });
                        }
                    }
                }
            }
        }

        // Looks for T1547.004: Winlogon Helper DLL
        // clang-format off
        std::vector<RegistryValue> winlogons{ CheckValues(HKEY_LOCAL_MACHINE,
            L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", { 
                { L"Shell", L"explorer\\.exe,?", false, CheckSzRegexMatch },
                { L"UserInit", L"(C:\\\\(Windows|WINDOWS|windows)\\\\(System32|SYSTEM32|system32)\\\\)?(U|u)(SERINIT|"
                    "serinit)\\.(exe|EXE),?", false, CheckSzRegexMatch } 
            }, true, true) };
        // clang-format on

        for(auto& detection : winlogons) {
            CREATE_DETECTION_WITH_CONTEXT(Certainty::Moderate,
                                          RegistryDetectionData{ detection.key, detection,
                                                                 RegistryDetectionType::FileReference,
                                                                 detection.key.GetRawValue(detection.wValueName) },
                                          DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1547_004) });
        }

        std::vector<RegistryValue> notifies{ CheckKeyValues(
            HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", true, true) };
        for(auto& notify : CheckSubkeys(
                HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", true, true)) {
            if(notify.ValueExists(L"DllName")) {
                notifies.emplace_back(RegistryValue{ notify, L"DllName", *notify.GetValue<std::wstring>(L"DllName") });
            }
        }

        for(auto& detection : notifies) {
            CREATE_DETECTION_WITH_CONTEXT(Certainty::Moderate,
                                          RegistryDetectionData{ detection.key, detection,
                                                                 RegistryDetectionType::FileReference,
                                                                 detection.key.GetRawValue(detection.wValueName) },
                                          DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1547_004) });
        }

        // Looks for T1547.005: Security Support Provider
        RegistryKey lsa3{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" };
        RegistryKey lsa4{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig" };

        for(auto& key : { lsa3, lsa4 }) {
            auto packages{ key.GetValue<std::vector<std::wstring>>(L"Security Packages") };
            if(packages) {
                for(auto& package : *packages) {
                    if(package != L"\"\"") {
                        auto filepath = FileSystem::SearchPathExecutable(package + L".dll");

                        if(filepath && FileScanner::PerformQuickScan(*filepath)) {
                            // Can't use a macro since we need the shared_ptr of the detection
                            auto value{ Bluespawn::detections.AddDetection(
                                Detection{ RegistryDetectionData{
                                               RegistryValue{ key, L"Security Packages", std::move(package) },
                                               RegistryDetectionType::FileReference },
                                           DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1547_005) } },
                                Certainty::Moderate) };
                            detections.emplace_back(value);

                            // Since the security package is missing the dll extension, the scanner may not find the
                            // associated file
                            auto file{ Bluespawn::detections.AddDetection(
                                Detection{ FileDetectionData{ *filepath },
                                           DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1547_005) } },
                                Certainty::Weak) };
                            detections.emplace_back(file);

                            // Define the association ourself
                            file->info.AddAssociation(value, Association::Certain);
                            value->info.AddAssociation(file, Association::Certain);
                        }
                    }
                }
            }
        }

        // Looks for T1547.010: Port Monitors
        RegistryKey monitors{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors" };

        for(auto monitor : monitors.EnumerateSubkeys()) {
            if(monitor.ValueExists(L"Driver")) {
                auto filepath{ FileSystem::SearchPathExecutable(monitor.GetValue<std::wstring>(L"Driver").value()) };

                if(filepath && FileScanner::PerformQuickScan(*filepath)) {
                    CREATE_DETECTION_WITH_CONTEXT(Certainty::Moderate,
                                                  RegistryDetectionData{ *RegistryValue::Create(monitor, L"Driver"),
                                                                         RegistryDetectionType::FileReference },
                                                  DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1547_010) });
                }
            }
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1547::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events;

        // Looks for T1547.001: Registry Run Keys / Startup Folder
        for(auto key : RunKeys) {
            GetRegistryEvents(events, HKEY_LOCAL_MACHINE, key);
        }
        GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Command Processor");
        GetRegistryEvents(events, HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders");
        GetRegistryEvents(events, HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders");

        // Looks for T1547.002 (Authentication Package) and T1547.005 (Security Support Provider)
        GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", true, false, false);
        GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig", true, false,
                          false);

        // Looks for T1547.004: Winlogon Helper DLL
        GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
        GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Notify", true,
                          true, true);

        // Looks for T1547.010: Port Monitors
        GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors", false,
                          false, true);

        return events;
    }
}   // namespace Hunts
