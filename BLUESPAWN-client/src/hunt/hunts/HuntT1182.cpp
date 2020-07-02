#include "hunt/hunts/HuntT1182.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include "hunt/RegistryHunt.h"
#include "user/bluespawn.h"

using namespace Registry;

namespace Hunts {
    HuntT1182::HuntT1182() : Hunt(L"T1182 - AppCert DLLs") {
        dwCategoriesAffected = (DWORD) Category::Configurations;
        dwSourcesInvolved = (DWORD) DataSource::Registry;
        dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1182::RunHunt(const Scope& scope) {
        HUNT_INIT();
        Registry::RegistryKey key{ HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager" };
        if(key.ValueExists(L"AppCertDLLs")) {
            for(auto dll : *key.GetValue<std::vector<std::wstring>>(L"AppCertDLLs")) {
                CREATE_DETECTION(Certainty::Strong,
                                 RegistryDetectionData{ key, RegistryValue{ key, L"AppCertDLLs", std::move(dll) },
                                                        RegistryDetectionType::FileReference });
            }
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1182::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events;

        events.push_back(std::make_unique<RegistryEvent>(
            RegistryKey{ HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager" }));

        return events;
    }
}   // namespace Hunts
