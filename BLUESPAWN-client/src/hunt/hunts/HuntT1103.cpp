#include "hunt/hunts/HuntT1103.h"
#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include "hunt/RegistryHunt.h"
#include "user/bluespawn.h"

using namespace Registry;

namespace Hunts {
    HuntT1103::HuntT1103() : Hunt(L"T1103 - AppInit DLLs") {
        dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Processes;
        dwSourcesInvolved = (DWORD) DataSource::Registry;
        dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1103::RunHunt(const Scope& scope) {
        HUNT_INIT();

        // TODO: Fix data type of registry detections

        for(auto& detection :
            CheckValues(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                        {
                            { L"AppInit_Dlls", L"", false, CheckSzEmpty },
                            { L"LoadAppInit_Dlls", 0, false, CheckDwordEqual },
                            { L"RequireSignedAppInit_DLLs", 1, false, CheckDwordEqual },
                        },
                        true, false)) {
            CREATE_DETECTION(Certainty::Strong,
                             RegistryDetectionData{ detection, RegistryDetectionType::FileReference });
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1103::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events{};

        GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", true,
                          false, false);

        return events;
    }
}   // namespace Hunts
