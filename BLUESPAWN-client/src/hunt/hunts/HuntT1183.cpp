#include "hunt/hunts/HuntT1183.h"

#include "common/ThreadPool.h"
#include "common/Utils.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include "hunt/Hunt.h"
#include "hunt/RegistryHunt.h"
#include "user/bluespawn.h"

using namespace Registry;

namespace Hunts {
    HuntT1183::HuntT1183() : Hunt(L"T1183 - Image File Execution Options") {
        dwCategoriesAffected = (DWORD) Category::Configurations;
        dwSourcesInvolved = (DWORD) DataSource::Registry;
        dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
    }

    std::vector<std::reference_wrapper<Detection>> HuntT1183::RunHunt(IN CONST Scope& scope) {
        HUNT_INIT()

        auto IFEO = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File "
                                                     L"Execution Options" };
        for(auto subkey : IFEO.EnumerateSubkeys()) {
            std::vector<RegistryValue> values{ CheckValues(
                HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                {
                    { L"Debugger", L"", false, CheckSzEmpty },
                    { L"GlobalFlag", 0, false, [](DWORD d1, DWORD d2) { return !(d1 & 0x200); } },
                },
                true, false) };

            for(const auto& detection : values) {
                if(detection.wValueName == L"GlobalFlag") {
                    CREATE_DETECTION_WITH_CONTEXT(
                        Certainty::Strong, RegistryDetectionData{ detection, RegistryDetectionType::FileReference },
                        DetectionContext{ GetName() }, [detection]() {
                            detection.key.SetValue<DWORD>(L"GlobalFlag", std::get<DWORD>(detection.data) & ~0x200);
                        });
                } else {
                    CREATE_DETECTION(Certainty::Strong,
                                     RegistryDetectionData{ detection, RegistryDetectionType::FileReference });
                }
            }

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
                    CREATE_DETECTION(Certainty::Moderate,
                                     RegistryDetectionData{ detection, RegistryDetectionType::FileReference });
                }
            }
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1183::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events;

        Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE,
                                    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                                    true, false, true);

        return events;
    }
}   // namespace Hunts
