#include "hunt/hunts/HuntT1037.h"

#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"

#include "hunt/RegistryHunt.h"
#include "user/bluespawn.h"

using namespace Registry;

namespace Hunts {
    HuntT1037::HuntT1037() : Hunt(L"T1037 - Boot or Logon Initialization Scripts") {
        dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
        dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
        dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1037::RunHunt(const Scope& scope) {
        HUNT_INIT();

        // Looks for T1037.001: Logon Script (Windows)
        for(auto detection : CheckValues(HKEY_CURRENT_USER, L"Environment", { 
            { L"UserInitMprLogonScript", L"", false, CheckSzEmpty } 
        }, true, true)) {

            // Moderate contextual certainty due to the infequency of use for this registry value in legitimate cases
            CREATE_DETECTION_WITH_CONTEXT(Certainty::Moderate, RegistryDetectionData{ 
                detection.key, 
                detection,
                RegistryDetectionType::FileReference,
                detection.key.GetRawValue(detection.wValueName) 
            }, DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1037_001) });
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1037::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events;

        // Looks for T1037.001: Logon Script (Windows)
        Registry::GetRegistryEvents(events, HKEY_CURRENT_USER, L"Environment", true, true, false);

        return events;
    }
}   // namespace Hunts
