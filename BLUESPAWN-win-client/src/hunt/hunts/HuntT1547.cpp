#include "hunt/hunts/HuntT1547.h"

#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"

#include "hunt/RegistryHunt.h"
#include "scan/FileScanner.h"
#include "scan/ProcessScanner.h"
#include "user/bluespawn.h"

using namespace Registry;

#define RUN_KEY 0
#define COMMAND_PROCESSOR 1
#define STARTUP_FOLDER 2
#define STARTUP_ITEMS 3
#define AUTH_PACKAGE 4
#define LSA_EXTENSION 5
#define WINLOGON 6
#define WINLOGON_NOTIFY 7
#define SSP 8
#define PORT_MON 9
#define TIME_PROV 10

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

    void HuntT1547::Subtechnique001(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections) {
        SUBTECHNIQUE_INIT(001, Registry Run Keys / Startup Folder);

        SUBSECTION_INIT(RUN_KEY, Cursory);
        for(auto& key : RunKeys) {
            for(auto& detection : CheckKeyValues(HKEY_LOCAL_MACHINE, key)) {
                if(ProcessScanner::PerformQuickScan(std::get<std::wstring>(detection.data))) {
                    CREATE_DETECTION(Certainty::Moderate,
                                     RegistryDetectionData{ detection, RegistryDetectionType::CommandReference });
                }
            }
        }
        SUBSECTION_END();

        SUBSECTION_INIT(COMMAND_PROCESSOR, Cursory);
        for(auto& detection : CheckValues(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Command Processor",
                                          { { L"AutoRun", L"", false, CheckSzEmpty } })) {
            CREATE_DETECTION(Certainty::Strong,
                             RegistryDetectionData{ detection, RegistryDetectionType::CommandReference });
        }
        SUBSECTION_END();

        SUBSECTION_INIT(STARTUP_FOLDER, Cursory);
        for(auto& detection : CheckValues(
                HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
                { { L"Startup", L"%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                    false, CheckSzEqual } })) {
            CREATE_DETECTION(Certainty::Moderate,
                             RegistryDetectionData{ detection, RegistryDetectionType::FolderReference });
        }

        for(auto& detection :
            CheckValues(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
                        { { L"Common Startup", L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                            false, CheckSzEqual } })) {
            CREATE_DETECTION(Certainty::Moderate,
                             RegistryDetectionData{ detection, RegistryDetectionType::FolderReference });
        }
        SUBSECTION_END();

        SUBSECTION_INIT(STARTUP_ITEMS, Cursory);
        std::vector<FileSystem::Folder> startup_directories = { FileSystem::Folder(
            L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp") };
        auto userFolders = FileSystem::Folder{ L"C:\\Users" }.GetSubdirectories(1);
        for(auto userFolder : userFolders) {
            FileSystem::Folder folder{ userFolder.GetFolderPath() + L"\\AppData\\Roaming\\Microsoft\\Windows\\Start "
                                                                    L"Menu\\Programs\\StartUp" };
            if(folder.GetFolderExists()) {
                startup_directories.emplace_back(folder);
            }
        }
        for(auto folder : startup_directories) {
            LOG_VERBOSE(1, L"Scanning " << folder.GetFolderPath());
            for(auto value : folder.GetFiles(std::nullopt, -1)) {
                if(FileScanner::PerformQuickScan(value.GetFilePath())) {
                    CREATE_DETECTION(Certainty::Weak, FileDetectionData{ value });
                }
            }
        }
        SUBSECTION_END();

        SUBTECHNIQUE_END();
    }

    void HuntT1547::Subtechnique002(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections) {
        SUBTECHNIQUE_INIT(002, Authentication Package);

        SUBSECTION_INIT(AUTH_PACKAGE, Cursory);
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
                                       DetectionContext{ __name } },
                            Certainty::Moderate) };
                        detections.emplace_back(value);

                        // Since the security package is missing the dll extension, the scanner may not find the
                        // associated file
                        auto file{ Bluespawn::detections.AddDetection(
                            Detection{ FileDetectionData{ *filepath }, DetectionContext{ __name } }, Certainty::Weak) };
                        detections.emplace_back(file);

                        // Define the association here since the scanner may not pick up on it
                        file->info.AddAssociation(value, Association::Certain);
                        value->info.AddAssociation(file, Association::Certain);
                    }
                }
            }
        }
        SUBSECTION_END();

        SUBSECTION_INIT(LSA_EXTENSION, Cursory);
        auto lsaext = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\LsaExtensionConfig" };
        for(auto subkeyName : lsaext.EnumerateSubkeyNames()) {
            if(subkeyName == L"Interfaces") {
                for(auto subkey : RegistryKey{ lsaext, L"Interfaces" }.EnumerateSubkeys()) {
                    auto ext{ RegistryValue::Create(subkey, L"Extension") };
                    if(ext && FileScanner::PerformQuickScan(ext->ToString())) {
                        CREATE_DETECTION(Certainty::Moderate,
                                         RegistryDetectionData{ *ext, RegistryDetectionType::FileReference });
                    }
                }
            } else {
                auto subkey = RegistryKey{ lsaext, subkeyName };
                auto exts = subkey.GetValue<std::vector<std::wstring>>(L"Extensions");
                if(exts) {
                    for(auto ext : *exts) {
                        if(FileScanner::PerformQuickScan(ext)) {
                            CREATE_DETECTION(
                                Certainty::Moderate,
                                RegistryDetectionData{ RegistryValue{ subkey, L"Extensions", std::move(ext) },
                                                       RegistryDetectionType::FileReference });
                        }
                    }
                }
            }
        }
        SUBSECTION_END();

        SUBTECHNIQUE_END();
    }

    void HuntT1547::Subtechnique003(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections){
        SUBTECHNIQUE_INIT(003, Time Providers);

        SUBSECTION_INIT(TIME_PROV, Cursory);
        RegistryKey time{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders" };
        for(auto subkey : time.EnumerateSubkeys()){
            if(auto value{ RegistryValue::Create(subkey, L"DllName") }){
                auto path{ FileSystem::SearchPathExecutable(std::get<std::wstring>(value->data)) };
                if(path && FileScanner::PerformQuickScan(*path)){
                    CREATE_DETECTION(Certainty::Moderate, RegistryDetectionData{ *value });
                }
            }
        }
        SUBSECTION_END();

        SUBTECHNIQUE_END();
    }
    
    void HuntT1547::Subtechnique004(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections) {
        SUBTECHNIQUE_INIT(004, Winlogon Helper DLL);

        SUBSECTION_INIT(WINLOGON, Cursory);
        // clang-format off
        auto userinitRegex{ 
            L"(C:\\\\[Ww](INDOWS|indows)\\\\[Ss](YSTEM32|ystem32)\\\\)?[Uu](SERINIT|serinit)\\.(exe|EXE),?" };
        std::vector<RegistryValue> winlogons{ CheckValues(HKEY_LOCAL_MACHINE,
            L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", {
                { L"Shell", L"explorer\\.exe,?", false, CheckSzRegexMatch },
                { L"UserInit", userinitRegex, false, CheckSzRegexMatch }
            }, true, true) };
        // clang-format on

        for(auto& detection : winlogons) {
            // Moderate contextual certainty due to how rarely these values are used legitimately
            CREATE_DETECTION(Certainty::Moderate, RegistryDetectionData{ detection, RegistryDetectionType::FileReference });
        }
        SUBSECTION_END();

        SUBSECTION_INIT(WINLOGON_NOTIFY, Cursory);
        std::vector<RegistryValue> notifies{ CheckKeyValues(
            HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", true, true) };
        for(auto& notify : CheckSubkeys(
                HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", true, true)) {
            if(notify.ValueExists(L"DllName")) {
                notifies.emplace_back(RegistryValue{ notify, L"DllName", *notify.GetValue<std::wstring>(L"DllName") });
            }
        }

        for(auto& detection : notifies) {
            // Weak contextual certainty due to how rarely these values are used legitimately
            CREATE_DETECTION(Certainty::Weak, RegistryDetectionData{ detection, RegistryDetectionType::FileReference });
        }
        SUBSECTION_END();

        SUBTECHNIQUE_END();
    }

    void HuntT1547::Subtechnique005(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections) {
        SUBTECHNIQUE_INIT(005, Security Support Provider);

        SUBSECTION_INIT(SSP, Cursory);
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
                                           DetectionContext{ __name } },
                                Certainty::Moderate) };
                            detections.emplace_back(value);

                            // Since the security package is missing the dll extension, the scanner may not find the
                            // associated file
                            auto file{ Bluespawn::detections.AddDetection(Detection{ FileDetectionData{ *filepath },
                                                                                     DetectionContext{ __name } },
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
        SUBSECTION_END();

        SUBTECHNIQUE_END();
    }

    void HuntT1547::Subtechnique010(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections) {
        SUBTECHNIQUE_INIT(010, Port Monitors);

        SUBSECTION_INIT(PORT_MON, Cursory);
        RegistryKey monitors{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors" };

        for(auto monitor : monitors.EnumerateSubkeys()) {
            if(monitor.ValueExists(L"Driver")) {
                auto filepath{ FileSystem::SearchPathExecutable(monitor.GetValue<std::wstring>(L"Driver").value()) };

                if(filepath && FileScanner::PerformQuickScan(*filepath)) {
                    CREATE_DETECTION(Certainty::Moderate,
                                     RegistryDetectionData{ *RegistryValue::Create(monitor, L"Driver"),
                                                            RegistryDetectionType::FileReference });
                }
            }
        }
        SUBSECTION_END();

        SUBTECHNIQUE_END();
    }

    std::vector<std::shared_ptr<Detection>> HuntT1547::RunHunt(const Scope& scope) {
        HUNT_INIT();

        Subtechnique001(scope, detections);
        Subtechnique002(scope, detections);
        Subtechnique003(scope, detections);
        Subtechnique004(scope, detections);
        Subtechnique005(scope, detections);
        Subtechnique010(scope, detections);

        HUNT_END();
    }

    std::vector<std::pair<std::unique_ptr<Event>, Scope>> HuntT1547::GetMonitoringEvents() {
        std::vector<std::pair<std::unique_ptr<Event>, Scope>> events;

        // Looks for T1547.001: Registry Run Keys / Startup Folder
        for(auto key : RunKeys) {
            GetRegistryEvents(events, SCOPE(RUN_KEY), HKEY_LOCAL_MACHINE, key);
        }
        GetRegistryEvents(events, SCOPE(COMMAND_PROCESSOR), HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Command Processor");
        GetRegistryEvents(events, SCOPE(STARTUP_FOLDER), HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders");
        GetRegistryEvents(events, SCOPE(STARTUP_FOLDER), HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders");
        auto userFolders = FileSystem::Folder(L"C:\\Users").GetSubdirectories(1);
        for(auto userFolder : userFolders) {
            FileSystem::Folder folder{ userFolder.GetFolderPath() + L"\\AppData\\Roaming\\Microsoft\\Windows\\Start "
                                                                    L"Menu\\Programs\\StartUp" };
            if(folder.GetFolderExists()) {
                events.push_back(
                    std::make_pair(std::make_unique<FileEvent>(folder), SCOPE(STARTUP_ITEMS)));
            }
        }

        // Looks for T1547.002 (Authentication Package) and T1547.005 (Security Support Provider)
        GetRegistryEvents(events, Scope::CreateSubhuntScope((1 << SSP) | (1 << AUTH_PACKAGE)), HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Control\\Lsa", false, false);
        GetRegistryEvents(events, Scope::CreateSubhuntScope((1 << SSP) | (1 << AUTH_PACKAGE)), HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig", false, false);
        GetRegistryEvents(events, SCOPE(LSA_EXTENSION), HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Control\\LsaExtensionConfig", false, false);

        // Looks for T1547.003: Time Provider
        GetRegistryEvents(events, SCOPE(TIME_PROV), HKEY_LOCAL_MACHINE,
                          L"System\\CurrentControlSet\\Services\\W32Time\\TimeProviders", false, false, true);

        // Looks for T1547.004: Winlogon Helper DLL
        GetRegistryEvents(events, SCOPE(WINLOGON), HKEY_LOCAL_MACHINE,
                          L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
        GetRegistryEvents(events, SCOPE(WINLOGON_NOTIFY), HKEY_LOCAL_MACHINE,
                          L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", true, true, true);

        // Looks for T1547.010: Port Monitors
        GetRegistryEvents(events, SCOPE(PORT_MON), HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors", false, false, true);

        return events;
    }
}   // namespace Hunts
