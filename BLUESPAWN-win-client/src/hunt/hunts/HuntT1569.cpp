#include "hunt/hunts/HuntT1569.h"

#include "util/Utils.h"
#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"
#include "util/processes/CheckLolbin.h"
#include "util/processes/ProcessUtils.h"

#include "hunt/RegistryHunt.h"
#include "scan/FileScanner.h"
#include "scan/ProcessScanner.h"
#include "user/bluespawn.h"

using namespace Registry;

namespace Hunts {
    HuntT1569::HuntT1569() : Hunt(L"T1569 - Service Execution") {
        dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files | (DWORD) Category::Processes;
        dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
        dwTacticsUsed = (DWORD) Tactic::Execution;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1569::RunHunt(const Scope& scope) {
        HUNT_INIT();

        // Looks for T1569.002: Service Execution
        auto services = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services" };

        for(auto service : services.EnumerateSubkeys()) {
            if(service.GetValue<DWORD>(L"Type") >= 0x10u) {
                auto cmd{ Registry::RegistryValue::Create(service, L"ImagePath") };
                if(ProcessScanner::PerformQuickScan(cmd->ToString())) {
                    CREATE_DETECTION_WITH_CONTEXT(
                        Certainty::Moderate, RegistryDetectionData{ *cmd, RegistryDetectionType::CommandReference },
                        DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1569_002) });
                }

                RegistryKey subkey = RegistryKey{ service, L"Parameters" };
                for(auto regkey : { service, subkey }) {
                    auto svcdll{ Registry::RegistryValue::Create(regkey, L"ServiceDll") };
                    if(svcdll && FileScanner::PerformQuickScan(svcdll->ToString())) {
                        CREATE_DETECTION_WITH_CONTEXT(
                            Certainty::Moderate, RegistryDetectionData{ *svcdll, RegistryDetectionType::FileReference },
                            DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1569_002) });
                    }
                }
            }
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1569::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events;

        // Looks for T1569.002: Service Execution
        GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", false, false, true);

        return events;
    }
}   // namespace Hunts
