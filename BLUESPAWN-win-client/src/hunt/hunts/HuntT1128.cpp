#include "hunt/hunts/HuntT1128.h"

#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"
#include "util/processes/ProcessUtils.h"

#include "hunt/RegistryHunt.h"
#include "scan/FileScanner.h"
#include "user/bluespawn.h"

using namespace Registry;

namespace Hunts {

    HuntT1128::HuntT1128() : Hunt(L"T1128 - Netsh Helper DLL") {
        dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
        dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
        dwTacticsUsed = (DWORD) Tactic::Persistence;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1128::RunHunt(const Scope& scope) {
        HUNT_INIT();

        auto netshKey = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Netsh", true };

        for(auto& helperDllValue : CheckKeyValues(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Netsh", true, false)) {
            if(FileScanner::PerformQuickScan(helperDllValue.ToString())) {
                CREATE_DETECTION(Certainty::Moderate,
                                 RegistryDetectionData{ helperDllValue, RegistryDetectionType::FileReference });
            }
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1128::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events;

        Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Netsh", true, false, false);

        return events;
    }
}   // namespace Hunts
