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

#define REGISTRY_SERVICES 0

namespace Hunts {
    HuntT1569::HuntT1569() : Hunt(L"T1569 - Service Execution") {
        dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files | (DWORD) Category::Processes;
        dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
        dwTacticsUsed = (DWORD) Tactic::Execution;
    }

    void HuntT1569::Subtechnique002(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections) {
        SUBTECHNIQUE_INIT(2, Service Execution);

        SUBSECTION_INIT(REGISTRY_SERVICES, Normal);
        auto services = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services" };

        for(auto service : services.EnumerateSubkeys()) {
            if(service.GetValue<DWORD>(L"Type") >= 0x10u) {
                auto cmd{ Registry::RegistryValue::Create(service, L"ImagePath") };
                if(ProcessScanner::PerformQuickScan(cmd->ToString())) {
                    CREATE_DETECTION(Certainty::Moderate,
                                     RegistryDetectionData{ *cmd, RegistryDetectionType::CommandReference });
                }

                RegistryKey subkey = RegistryKey{ service, L"Parameters" };
                for(auto regkey : { service, subkey }) {
                    auto svcdll{ Registry::RegistryValue::Create(regkey, L"ServiceDll") };
                    if(svcdll && FileScanner::PerformQuickScan(svcdll->ToString())) {
                        CREATE_DETECTION(Certainty::Moderate,
                                         RegistryDetectionData{ *svcdll, RegistryDetectionType::FileReference });
                    }
                }
            }
        }
        SUBSECTION_END();

        SUBTECHNIQUE_END();
    }

    std::vector<std::shared_ptr<Detection>> HuntT1569::RunHunt(const Scope& scope) {
        HUNT_INIT();

        Subtechnique002(scope, detections);

        HUNT_END();
    }

    std::vector<std::pair<std::unique_ptr<Event>, Scope>> HuntT1569::GetMonitoringEvents() {
        std::vector<std::pair<std::unique_ptr<Event>, Scope>> events;

        // Looks for T1569.002: Service Execution
        GetRegistryEvents(events, SCOPE(REGISTRY_SERVICES), HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services",
                          false, false, true);

        return events;
    }
}   // namespace Hunts
