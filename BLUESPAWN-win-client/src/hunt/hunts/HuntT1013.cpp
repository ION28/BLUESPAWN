#include "hunt/hunts/HuntT1013.h"

#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"

#include "scan/FileScanner.h"
#include "user/bluespawn.h"

using namespace Registry;

namespace Hunts {

    HuntT1013::HuntT1013() : Hunt(L"T1013 - Port Monitors") {
        dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
        dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
        dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1013::RunHunt(const Scope& scope) {
        HUNT_INIT();

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

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1013::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events;

        Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors",
                                    false, false, true);

        return events;
    }
}   // namespace Hunts
