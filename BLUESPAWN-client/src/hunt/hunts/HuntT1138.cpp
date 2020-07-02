#include "hunt/hunts/HuntT1138.h"

#include "common/Utils.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include "hunt/RegistryHunt.h"
#include "user/bluespawn.h"

using namespace Registry;

namespace Hunts {
    HuntT1138::HuntT1138() : Hunt(L"T1138 - Application Shimming") {
        dwCategoriesAffected = (DWORD) Category::Configurations;
        dwSourcesInvolved = (DWORD) DataSource::Registry;
        dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1138::RunHunt(const Scope& scope) {
        HUNT_INIT();

        auto& values{ CheckKeyValues(HKEY_LOCAL_MACHINE,
                                     L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB",
                                     true, true) };
        ADD_ALL_VECTOR(values, CheckKeyValues(HKEY_LOCAL_MACHINE,
                                              L"SOFTWARE\\Microsoft\\Windows "
                                              L"NT\\CurrentVersion\\AppCompatFlags\\Custom",
                                              true, true));

        for(const auto& detection : values) {
            CREATE_DETECTION(Certainty::Strong, RegistryDetectionData{ detection, RegistryDetectionType::Unknown });
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1138::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events;

        GetRegistryEvents(events, HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB");
        GetRegistryEvents(events, HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom");

        return events;
    }
}   // namespace Hunts
