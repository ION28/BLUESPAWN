#include "hunt/hunts/HuntT1037.h"

#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"

#include "hunt/RegistryHunt.h"
#include "user/bluespawn.h"

using namespace Registry;

#define LOGON_SCRIPT 0

namespace Hunts {
    HuntT1037::HuntT1037() : Hunt(L"T1037 - Boot or Logon Initialization Scripts") {
        dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
        dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
        dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
    }

    void HuntT1037::Subtechnique001(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections) {
        SUBTECHNIQUE_INIT(001, Logon Script[Windows]);

        SUBSECTION_INIT(LOGON_SCRIPT, Cursory);
        for(auto detection : CheckValues(HKEY_CURRENT_USER, L"Environment",
                                         { { L"UserInitMprLogonScript", L"", false, CheckSzEmpty } }, true, true)) {
            // Moderate contextual certainty due to the infequency of use for this registry value in legitimate cases
            CREATE_DETECTION(Certainty::Moderate, RegistryDetectionData{ detection });
        }
        SUBSECTION_END();

        SUBTECHNIQUE_END();
    }

    std::vector<std::shared_ptr<Detection>> HuntT1037::RunHunt(const Scope& scope) {
        HUNT_INIT();

        Subtechnique001(scope, detections);

        HUNT_END();
    }

    std::vector<std::pair<std::unique_ptr<Event>, Scope>> HuntT1037::GetMonitoringEvents() {
        std::vector<std::pair<std::unique_ptr<Event>, Scope>> events;

        // Looks for T1037.001: Logon Script (Windows)
        Registry::GetRegistryEvents(events, SCOPE(LOGON_SCRIPT), HKEY_CURRENT_USER, L"Environment", true, true, false);

        return events;
    }
}   // namespace Hunts
