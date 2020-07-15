#include "hunt/hunts/HuntT1004.h"

#include <algorithm>

#include "common/ThreadPool.h"
#include "common/Utils.h"

#include "util/configurations/Registry.h"
#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"

#include "hunt/Hunt.h"
#include "hunt/RegistryHunt.h"
#include "user/bluespawn.h"

using namespace Registry;

namespace Hunts {

    HuntT1004::HuntT1004() : Hunt(L"T1004 - Winlogon Helper DLL") {
        dwCategoriesAffected = (DWORD) Category::Configurations;
        dwSourcesInvolved = (DWORD) DataSource::Registry;
        dwTacticsUsed = (DWORD) Tactic::Persistence;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1004::RunHunt(IN CONST Scope& scope) {
        HUNT_INIT();

        // clang-format off
        std::vector<RegistryValue> winlogons{ CheckValues(HKEY_LOCAL_MACHINE,
            L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", { 
                { L"Shell", L"explorer\\.exe,?", false, CheckSzRegexMatch },
                { L"UserInit", L"(C:\\\\(Windows|WINDOWS|windows)\\\\(System32|SYSTEM32|system32)\\\\)?(U|u)(SERINIT|"
                    "serinit)\\.(exe|EXE),?", false, CheckSzRegexMatch } 
            }, true, true) };
        // clang-format on

        for(auto& detection : winlogons) {
            CREATE_DETECTION(Certainty::Moderate,
                             RegistryDetectionData{ detection.key, detection, RegistryDetectionType::FileReference,
                                                    detection.key.GetRawValue(detection.wValueName) });
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
            CREATE_DETECTION(Certainty::Moderate,
                             RegistryDetectionData{ detection.key, detection, RegistryDetectionType::FileReference,
                                                    detection.key.GetRawValue(detection.wValueName) });
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1004::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events{};

        Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE,
                                    L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
        Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE,
                                    L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Notify", true, true, true);

        return events;
    }
}   // namespace Hunts
