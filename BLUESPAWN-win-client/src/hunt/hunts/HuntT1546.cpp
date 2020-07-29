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

    std::vector<std::shared_ptr<Detection>> HuntT1546::RunHunt(IN CONST Scope& scope) {
        HUNT_INIT();

        // Looks for T1546.007: Netsh Helper DLL
        for(auto& helperDllValue : CheckKeyValues(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Netsh", true, false)) {
            if(FileScanner::PerformQuickScan(helperDllValue.ToString())) {
                CREATE_DETECTION_WITH_CONTEXT(
                    Certainty::Moderate, RegistryDetectionData{ helperDllValue, RegistryDetectionType::FileReference },
                    DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1546_007) });
            }
        }

        // Looks for T1546.008: Accessibility Features
        for(auto& key : vAccessibilityBinaries) {
            std::vector<RegistryValue> debugger{ CheckValues(HKEY_LOCAL_MACHINE, wsIFEO + key,
                                                             {
                                                                 { L"Debugger", L"", false, CheckSzEmpty },
                                                             },
                                                             true, false) };
            for(auto& detection : debugger) {
                CREATE_DETECTION_WITH_CONTEXT(Certainty::Certain,
                                              RegistryDetectionData{ detection.key, detection,
                                                                     RegistryDetectionType::CommandReference,
                                                                     detection.key.GetRawValue(detection.wValueName) },
                                              DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1546_008) });
            }
        }

        for(auto name : vAccessibilityBinaries) {
            FileSystem::File file{ FileSystem::File(L"C:\\Windows\\System32\\" + name) };

            if(!file.IsMicrosoftSigned()) {
                CREATE_DETECTION_WITH_CONTEXT(Certainty::Certain, FileDetectionData{ file },
                                              DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1546_008) });
            }
        }

        // Looks for T1546.009: AppCert DLLs
        Registry::RegistryKey appcert_key{ HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager" };
        if(appcert_key.ValueExists(L"AppCertDLLs")) {
            for(auto dll : *appcert_key.GetValue<std::vector<std::wstring>>(L"AppCertDLLs")) {
                CREATE_DETECTION_WITH_CONTEXT(
                    Certainty::Strong,
                    RegistryDetectionData{ appcert_key, RegistryValue{ appcert_key, L"AppCertDLLs", std::move(dll) },
                                           RegistryDetectionType::FileReference },
                    DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1546_009) });
            }
        }

        // Looks for T1546.010: AppInit DLLs
        for(auto& detection :
            CheckValues(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                        {
                            { L"AppInit_Dlls", L"", false, CheckSzEmpty },
                            { L"LoadAppInit_Dlls", 0, false, CheckDwordEqual },
                            { L"RequireSignedAppInit_DLLs", 1, false, CheckDwordEqual },
                        },
                        true, false)) {
            CREATE_DETECTION_WITH_CONTEXT(Certainty::Strong,
                                          RegistryDetectionData{ detection,
                                                                 detection.type == RegistryType::REG_DWORD_T ?
                                                                     RegistryDetectionType::Configuration :
                                                                     RegistryDetectionType::FileReference },
                                          DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1546_010) });
        }

        // Looks for T1546.011: Application Shimming
        auto& shims{ CheckKeyValues(HKEY_LOCAL_MACHINE,
                                    L"SOFTWARE\\Microsoft\\Windows "
                                    L"NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB",
                                    true, true) };
        ADD_ALL_VECTOR(shims, CheckKeyValues(HKEY_LOCAL_MACHINE,
                                             L"SOFTWARE\\Microsoft\\Windows "
                                             L"NT\\CurrentVersion\\AppCompatFlags\\Custom",
                                             true, true));

        for(const auto& detection : shims) {
            CREATE_DETECTION_WITH_CONTEXT(Certainty::Strong,
                                          RegistryDetectionData{ detection, RegistryDetectionType::Unknown },
                                          DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1546_011) });
        }

        // Looks for T1546.012: Image File Execution Options Injection
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
                        DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1546_012) }, [detection]() {
                            detection.key.SetValue<DWORD>(L"GlobalFlag", std::get<DWORD>(detection.data) & ~0x200);
                        });
                } else {
                    CREATE_DETECTION_WITH_CONTEXT(
                        Certainty::Strong, RegistryDetectionData{ detection, RegistryDetectionType::FileReference },
                        DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1546_012) });
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
                        CREATE_DETECTION_WITH_CONTEXT(Certainty::Moderate,
                                                      RegistryDetectionData{ detection,
                                                                             RegistryDetectionType::Configuration },
                                                      DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1546_012) });
                    } else {
                        CREATE_DETECTION_WITH_CONTEXT(Certainty::Moderate,
                                                      RegistryDetectionData{ detection,
                                                                             RegistryDetectionType::FileReference },
                                                      DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1546_012) });
                    }
                }
            }
        }

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
                        CREATE_DETECTION_WITH_CONTEXT(
                            Certainty::Moderate,
                            RegistryDetectionData{ value, dll ? RegistryDetectionType::FileReference :
                                                                RegistryDetectionType::CommandReference },
                            DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1546_015) });
                    }
                }
            }
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1546::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events;

        // Looks for T1546.007: Netsh Helper DLL
        GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Netsh", true, false, false);

        // Looks for T1546.008: Accessibility Features
        for(auto key : vAccessibilityBinaries) {
            Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE, wsIFEO + key, true, false, false);
        }

        // Looks for T1546.009: AppCert DLLs
        GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager", true,
                          false, false);

        // Looks for T1546.010: AppInit DLLs
        GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", true,
                          false, false);

        // Looks for T1546.011: Application Shimming
        GetRegistryEvents(events, HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB");
        GetRegistryEvents(events, HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom");
        events.push_back(std::make_unique<FileEvent>(FileSystem::Folder{ L"C:\\Windows\\AppPatch\\Custom" }));
        events.push_back(std::make_unique<FileEvent>(FileSystem::Folder{ L"C:\\Windows\\AppPatch\\Custom\\Custom64" }));

        // Looks for T1546.012: Image File Execution Options Injection
        Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE,
                                    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution "
                                    L"Options",
                                    true, false, true);

        // Looks for T1546.015: Component Object Model Hijacking
        if(Bluespawn::aggressiveness >= Aggressiveness::Intensive) {
            Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID", true, true, true);
        }

        return events;
    }
}   // namespace Hunts
