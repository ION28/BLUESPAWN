#include "hunt/hunts/HuntT1546.h"

#include <algorithm>

#include "util/StringUtils.h"
#include "util/Utils.h"
#include "util/configurations/Registry.h"
#include "util/filesystem/Filesystem.h"
#include "util/log/Log.h"
#include "util/processes/CheckLolbin.h"
#include "util/processes/ProcessUtils.h"

#include "hunt/RegistryHunt.h"
#include "scan/FileScanner.h"
#include "scan/ProcessScanner.h"
#include "user/bluespawn.h"

using namespace Registry;

#define NETSH_HELPER 0
#define ACCESSIBILITY_HIJACK 1
#define ACCESSIBILITY_REPLACE 2
#define APPCERT_DLL 3
#define APPINIT_DLL 4
#define APPLICATION_SHIM 5
#define IFEO_HIJACK 6
#define COM_HIJACK 7
#define SCREENSAVER_KEY 8
#define SCREENSAVER_FILE 9

namespace Hunts {

    HuntT1546::HuntT1546() : Hunt(L"T1546 - Event Triggered Execution") {
        dwCategoriesAffected = (DWORD) Category::Configurations;
        dwSourcesInvolved = (DWORD) DataSource::Registry;
        dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::DefenseEvasion;
    }

#define ADD_FILE(file, ...)                                             \
    if(files.find(file) != files.end()) {                               \
        files.at(file).emplace_back(__VA_ARGS__);                       \
    } else {                                                            \
        files.emplace(file, std::vector<RegistryValue>{ __VA_ARGS__ }); \
    }

    void HuntT1546::Subtechnique002(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections){
        SUBTECHNIQUE_INIT(002, Screensaver);

        SUBSECTION_INIT(SCREENSAVER_KEY, Cursory);
        for(const auto& detection : CheckValues(HKEY_CURRENT_USER, L"Control Panel\\Desktop",
                                                { { L"SCRNSAVE.exe", L"", false, CheckSzEmpty } })){
            CREATE_DETECTION(Certainty::None,
                             RegistryDetectionData{ detection, RegistryDetectionType::CommandReference });
        }
        SUBSECTION_END();

        SUBSECTION_INIT(SCREENSAVER_FILE, Cursory);
        auto path{ L"C:\\Windows\\System32\\scrnsave.scr" };
        if(FileSystem::CheckFileExists(path) && !FileSystem::File{ path }.GetFileSigned()){
            CREATE_DETECTION(Certainty::None, FileDetectionData{ path });
        }
        SUBSECTION_END();

        SUBTECHNIQUE_END();
    }

    void HuntT1546::Subtechnique007(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections) {
        SUBTECHNIQUE_INIT(7, Netsh Helper DLL);

        SUBSECTION_INIT(NETSH_HELPER, Cursory);
        for(auto& helperDllValue : CheckKeyValues(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Netsh", true, false)) {
            if(FileScanner::PerformQuickScan(helperDllValue.ToString())) {
                CREATE_DETECTION(Certainty::Moderate,
                                 RegistryDetectionData{ helperDllValue, RegistryDetectionType::FileReference });
            }
        }
        SUBSECTION_END();

        SUBTECHNIQUE_END();
    }
    void HuntT1546::Subtechnique008(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections) {
        SUBTECHNIQUE_INIT(8, Accessibility Features);

        SUBSECTION_INIT(ACCESSIBILITY_HIJACK, Cursory);
        for(auto& key : vAccessibilityBinaries) {
            std::vector<RegistryValue> debugger{ CheckValues(HKEY_LOCAL_MACHINE, wsIFEO + key,
                                                             {
                                                                 { L"Debugger", L"", false, CheckSzEmpty },
                                                             },
                                                             true, false) };
            for(auto& detection : debugger) {
                CREATE_DETECTION(Certainty::Certain,
                                 RegistryDetectionData{ detection.key, detection,
                                                        RegistryDetectionType::CommandReference,
                                                        detection.key.GetRawValue(detection.wValueName) });
            }
        }
        SUBSECTION_END();

        SUBSECTION_INIT(ACCESSIBILITY_REPLACE, Normal);
        for(auto name : vAccessibilityBinaries) {
            FileSystem::File file{ FileSystem::File(L"C:\\Windows\\System32\\" + name) };

            if(!file.IsMicrosoftSigned()) {
                CREATE_DETECTION(Certainty::Certain, FileDetectionData{ file });
            }
        }
        SUBSECTION_END();

        SUBTECHNIQUE_END();
    }
    void HuntT1546::Subtechnique009(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections) {
        SUBTECHNIQUE_INIT(9, AppCert DLLs);

        SUBSECTION_INIT(APPCERT_DLL, Cursory);
        Registry::RegistryKey appcert_key{ HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager" };
        if(appcert_key.ValueExists(L"AppCertDLLs")) {
            for(auto dll : *appcert_key.GetValue<std::vector<std::wstring>>(L"AppCertDLLs")) {
                CREATE_DETECTION(Certainty::Strong,
                                 RegistryDetectionData{ appcert_key,
                                                        RegistryValue{ appcert_key, L"AppCertDLLs", std::move(dll) },
                                                        RegistryDetectionType::FileReference });
            }
        }
        SUBSECTION_END();

        SUBTECHNIQUE_END();
    }
    void HuntT1546::Subtechnique010(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections) {
        SUBTECHNIQUE_INIT(10, AppInit DLLs);

        SUBSECTION_INIT(APPINIT_DLL, Cursory);
        for(auto& detection :
            CheckValues(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                        {
                            { L"AppInit_Dlls", L"", false, CheckSzEmpty },
                            { L"LoadAppInit_Dlls", 0, false, CheckDwordEqual },
                            { L"RequireSignedAppInit_DLLs", 1, false, CheckDwordEqual },
                        },
                        true, false)) {
            CREATE_DETECTION(Certainty::Strong,
                             RegistryDetectionData{ detection, detection.type == RegistryType::REG_DWORD_T ?
                                                                   RegistryDetectionType::Configuration :
                                                                   RegistryDetectionType::FileReference });
        }
        SUBSECTION_END();

        SUBTECHNIQUE_END();
    }
    void HuntT1546::Subtechnique011(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections) {
        SUBTECHNIQUE_INIT(11, Application Shimming);

        SUBSECTION_INIT(APPLICATION_SHIM, Normal);
        auto& shims{ CheckKeyValues(HKEY_LOCAL_MACHINE,
                                    L"SOFTWARE\\Microsoft\\Windows "
                                    L"NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB",
                                    true, true) };
        ADD_ALL_VECTOR(shims, CheckKeyValues(HKEY_LOCAL_MACHINE,
                                             L"SOFTWARE\\Microsoft\\Windows "
                                             L"NT\\CurrentVersion\\AppCompatFlags\\Custom",
                                             true, true));

        for(const auto& detection : shims) {
            CREATE_DETECTION(Certainty::Strong, RegistryDetectionData{ detection, RegistryDetectionType::Unknown });
        }
        SUBSECTION_END();

        SUBTECHNIQUE_END();
    }
    void HuntT1546::Subtechnique012(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections) {
        SUBTECHNIQUE_INIT(12, Image File Execution Options Injection);

        SUBSECTION_INIT(IFEO_HIJACK, Normal);
        auto IFEO = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File "
                                                     L"Execution Options" };
        for(auto name : IFEO.EnumerateSubkeyNames()) {
            std::vector<RegistryValue> values{ CheckValues(
                HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" + name,
                {
                    { L"Debugger", L"", false, CheckSzEmpty },
                    { L"GlobalFlag", 0, false, [](DWORD d1, DWORD d2) { return !(d1 & 0x200); } },
                },
                true, false) };

            for(const auto& detection : values) {
                if(detection.wValueName == L"GlobalFlag") {
                    CREATE_DETECTION_WITH_CONTEXT(
                        Certainty::Strong, RegistryDetectionData{ detection, RegistryDetectionType::FileReference },
                        DetectionContext{ __name }, [detection]() {
                            detection.key.SetValue<DWORD>(L"GlobalFlag", std::get<DWORD>(detection.data) & ~0x200);
                        });
                } else {
                    CREATE_DETECTION(Certainty::Strong,
                                     RegistryDetectionData{ detection, RegistryDetectionType::FileReference });
                }
            }

            RegistryKey subkey{ IFEO, name };
            auto GFlags = subkey.GetValue<DWORD>(L"GlobalFlag");
            if(GFlags && *GFlags & 0x200) {
                auto name = subkey.GetName();
                name = name.substr(name.find_last_of(L"\\") + 1);

                std::vector<RegistryValue> values2{ CheckValues(
                    HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\" + name,
                    {
                        { L"ReportingMode", 0, false, CheckDwordEqual },
                        { L"MonitorProcess", L"", false, CheckSzEmpty },
                    },
                    true, false) };

                for(const auto& detection : values2) {
                    if(detection.type == RegistryType::REG_DWORD_T) {
                        CREATE_DETECTION(Certainty::Moderate,
                                         RegistryDetectionData{ detection, RegistryDetectionType::Configuration });
                    } else {
                        CREATE_DETECTION(Certainty::Moderate,
                                         RegistryDetectionData{ detection, RegistryDetectionType::CommandReference });
                    }
                }
            }
        }
        SUBSECTION_END();

        SUBTECHNIQUE_END();
    }
    void HuntT1546::Subtechnique015(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections) {
        SUBTECHNIQUE_INIT(15, Component Object Model Hijacking);

        SUBSECTION_INIT(COM_HIJACK, Intensive);
        // Looks for T1546.015: Component Object Model Hijacking
        if(Bluespawn::aggressiveness >= Aggressiveness::Intensive) {
            std::map<std::wstring, std::vector<RegistryValue>> files{};

            for(auto key : CheckSubkeys(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID", true, true)) {
                RegistryKey subkey{ key, L"InprocServer32" };
                if(subkey.Exists() && subkey.ValueExists(L"")) {
                    auto filename{ *subkey.GetValue<std::wstring>(L"") };
                    auto path{ FileSystem::SearchPathExecutable(filename) };
                    if(path) {
                        ADD_FILE(*path, RegistryValue{ subkey, L"", std::move(filename) });
                    }
                }
                subkey = { key, L"InprocServer" };
                if(subkey.Exists() && subkey.ValueExists(L"")) {
                    auto filename{ *subkey.GetValue<std::wstring>(L"") };
                    auto path{ FileSystem::SearchPathExecutable(filename) };
                    if(path) {
                        ADD_FILE(*path, RegistryValue{ subkey, L"", std::move(filename) });
                    }
                }
                if(key.ValueExists(L"InprocHandler32")) {
                    auto filename{ *key.GetValue<std::wstring>(L"InprocHandler32") };
                    auto path{ FileSystem::SearchPathExecutable(filename) };
                    if(path) {
                        ADD_FILE(*path, RegistryValue{ key, L"InprocHandler32", std::move(filename) });
                    }
                }
                if(key.ValueExists(L"InprocHandler")) {
                    auto filename{ *key.GetValue<std::wstring>(L"InprocHandler") };
                    auto path{ FileSystem::SearchPathExecutable(filename) };
                    if(path) {
                        ADD_FILE(*path, RegistryValue{ key, L"InprocHandler", std::move(filename) });
                    }
                }
                if(key.ValueExists(L"LocalServer")) {
                    auto filename{ *key.GetValue<std::wstring>(L"LocalServer") };
                    ADD_FILE(filename, RegistryValue{ key, L"LocalServer", *subkey.GetValue<std::wstring>(L"") });
                }
                subkey = { key, L"LocalServer32" };
                if(subkey.Exists() && subkey.ValueExists(L"")) {
                    auto filename{ *subkey.GetValue<std::wstring>(L"") };
                    ADD_FILE(filename, RegistryValue{ subkey, L"", *subkey.GetValue<std::wstring>(L"") });
                }
                if(subkey.Exists() && subkey.ValueExists(L"ServerExecutable")) {
                    auto filename{ *subkey.GetValue<std::wstring>(L"ServerExecutable") };
                    ADD_FILE(filename,
                             RegistryValue{ subkey, L"ServerExecutable", *subkey.GetValue<std::wstring>(L"") });
                }
            }

            for(auto pair : files) {
                auto path{ pair.first };
                if(!FileSystem::CheckFileExists(path)) {
                    path = GetImagePathFromCommand(path);
                    if(!FileSystem::CheckFileExists(path)) {
                        continue;
                    }
                }

                auto dll{ path.find(L".dll") != std::wstring::npos };
                if((dll && FileScanner::PerformQuickScan(path)) ||
                   (!dll && ProcessScanner::PerformQuickScan(pair.first))) {
                    for(auto& value : pair.second) {
                        CREATE_DETECTION(Certainty::Moderate,
                                         RegistryDetectionData{ value, dll ? RegistryDetectionType::FileReference :
                                                                             RegistryDetectionType::CommandReference });
                    }
                }
            }
        }
        SUBSECTION_END();

        SUBTECHNIQUE_END();
    }

    std::vector<std::shared_ptr<Detection>> HuntT1546::RunHunt(IN CONST Scope& scope) {
        HUNT_INIT();

        Subtechnique002(scope, detections);
        Subtechnique007(scope, detections);
        Subtechnique008(scope, detections);
        Subtechnique009(scope, detections);
        Subtechnique010(scope, detections);
        Subtechnique011(scope, detections);
        Subtechnique012(scope, detections);
        Subtechnique015(scope, detections);

        HUNT_END();
    }

    std::vector<std::pair<std::unique_ptr<Event>, Scope>> HuntT1546::GetMonitoringEvents() {
        std::vector<std::pair<std::unique_ptr<Event>, Scope>> events;

        // Looks for T1546.002: Screensaver
        GetRegistryEvents(events, SCOPE(SCREENSAVER_KEY), HKEY_CURRENT_USER, L"Control Panel\\Desktop", true, false,
                          false);

        // Looks for T1546.007: Netsh Helper DLL
        GetRegistryEvents(events, SCOPE(NETSH_HELPER), HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Netsh", true, false,
                          false);

        // Looks for T1546.008: Accessibility Features
        for(auto key : vAccessibilityBinaries) {
            Registry::GetRegistryEvents(events, SCOPE(ACCESSIBILITY_HIJACK), HKEY_LOCAL_MACHINE, wsIFEO + key, true,
                                        false, false);
        }

        // Looks for T1546.009: AppCert DLLs
        GetRegistryEvents(events, SCOPE(APPCERT_DLL), HKEY_LOCAL_MACHINE,
                          L"System\\CurrentControlSet\\Control\\Session Manager", true, false, false);

        // Looks for T1546.010: AppInit DLLs
        GetRegistryEvents(events, SCOPE(APPINIT_DLL), HKEY_LOCAL_MACHINE,
                          L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", true, false, false);

        // Looks for T1546.011: Application Shimming
        GetRegistryEvents(events, SCOPE(APPLICATION_SHIM), HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB");
        GetRegistryEvents(events, SCOPE(APPLICATION_SHIM), HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom");
        events.push_back(
            std::make_pair(std::make_unique<FileEvent>(FileSystem::Folder{ L"C:\\Windows\\AppPatch\\Custom" }),
                           SCOPE(APPLICATION_SHIM)));
        events.push_back(std::make_pair(std::make_unique<FileEvent>(FileSystem::Folder{ L"C:"
                                                                                        L"\\Windows\\AppPatch\\Custom\\"
                                                                                        L"Custom64" }),
                                        SCOPE(APPLICATION_SHIM)));

        // Looks for T1546.012: Image File Execution Options Injection
        Registry::GetRegistryEvents(events, SCOPE(IFEO_HIJACK), HKEY_LOCAL_MACHINE,
                                    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                                    true, false, true);

        // Looks for T1546.015: Component Object Model Hijacking
        if(Bluespawn::aggressiveness >= Aggressiveness::Intensive) {
            Registry::GetRegistryEvents(events, SCOPE(COM_HIJACK), HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID",
                                        true, true, true);
        }

        return events;
    }
}   // namespace Hunts
