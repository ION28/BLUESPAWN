#include "hunt/hunts/HuntT1101.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include "hunt/RegistryHunt.h"
#include "user/bluespawn.h"

using namespace Registry;

namespace Hunts {
    HuntT1101::HuntT1101() : Hunt(L"T1101 - Security Support Provider") {
        dwCategoriesAffected = (DWORD) Category::Configurations;
        dwSourcesInvolved = (DWORD) DataSource::Registry;
        dwTacticsUsed = (DWORD) Tactic::Persistence;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1101::RunHunt(const Scope& scope) {
        HUNT_INIT();

        Registry::RegistryKey key{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" };
        if(key.ValueExists(L"Security Packages")) {
            for(auto package : *key.GetValue<std::vector<std::wstring>>(L"Security Packages")) {
                if(okSecPackages.find(package) == okSecPackages.end()) {
                    CREATE_DETECTION(
                        Certainty::Moderate,
                        RegistryDetectionData{ key, RegistryValue{ key, L"Security Packages", std::move(package) },
                                               RegistryDetectionType::FileReference });
                }
            }
        }

        key = { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig" };
        if(key.ValueExists(L"Security Packages")) {
            for(auto package : *key.GetValue<std::vector<std::wstring>>(L"Security Packages")) {
                if(okSecPackages.find(package) == okSecPackages.end()) {
                    CREATE_DETECTION(
                        Certainty::Moderate,
                        RegistryDetectionData{ key, RegistryValue{ key, L"Security Packages", std::move(package) },
                                               RegistryDetectionType::FileReference });
                }
            }
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1101::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events;

        events.push_back(std::make_unique<RegistryEvent>(RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\"
                                                                                          L"Control\\Lsa" }));
        events.push_back(std::make_unique<RegistryEvent>(RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\"
                                                                                          L"Control\\Lsa\\OSConfig" }));

        return events;
    }
}   // namespace Hunts
