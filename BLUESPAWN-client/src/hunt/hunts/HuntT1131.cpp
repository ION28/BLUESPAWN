#include "hunt/hunts/HuntT1131.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include "hunt/RegistryHunt.h"
#include "user/bluespawn.h"

using namespace Registry;

namespace Hunts {
    HuntT1131::HuntT1131() : Hunt(L"T1131 - Authentication Package") {
        dwCategoriesAffected = (DWORD) Category::Configurations;
        dwSourcesInvolved = (DWORD) DataSource::Registry;
        dwTacticsUsed = (DWORD) Tactic::Persistence;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1131::RunHunt(const Scope& scope) {
        HUNT_INIT();

        Registry::RegistryKey key{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" };
        if(key.ValueExists(L"Authentication Packages")) {
            for(auto package : *key.GetValue<std::vector<std::wstring>>(L"Authentication Packages")) {
                if(okAuthPackages.find(package) == okAuthPackages.end()) {
                    CREATE_DETECTION(Certainty::Moderate,
                                     RegistryDetectionData{
                                         key, RegistryValue{ key, L"Authentication Packages", std::move(package) },
                                         RegistryDetectionType::FileReference });
                }
            }
        }
        if(key.ValueExists(L"Notification Packages")) {
            for(auto package : *key.GetValue<std::vector<std::wstring>>(L"Notification Packages")) {
                if(okNotifPackages.find(package) == okNotifPackages.end()) {
                    CREATE_DETECTION(
                        Certainty::Moderate,
                        RegistryDetectionData{ key, RegistryValue{ key, L"Notification Packages", std::move(package) },
                                               RegistryDetectionType::FileReference });
                }
            }
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1131::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events;

        events.push_back(std::make_unique<RegistryEvent>(RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\"
                                                                                          L"Control\\Lsa" }));

        return events;
    }
}   // namespace Hunts
