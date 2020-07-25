#include "hunt/hunts/HuntT1089.h"

#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"

#include "scan/FileScanner.h"
#include "user/bluespawn.h"

using namespace Registry;

namespace Hunts {

    HuntT1089::HuntT1089() : Hunt(L"T1089 - Disabling Security Tools") {
        dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Network;
        dwSourcesInvolved = (DWORD) DataSource::Registry;
        dwTacticsUsed = (DWORD) Tactic::DefenseEvasion;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1089::RunHunt(const Scope& scope) {
        HUNT_INIT();

        RegistryKey DomainProfile{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters"
                                                       L"\\FirewallPolicy\\DomainProfile" };
        RegistryKey StandardProfile{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameter"
                                                         L"s\\FirewallPolicy\\StandardProfile" };
        RegistryKey PublicProfile{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters"
                                                       L"\\FirewallPolicy\\PublicProfile" };

        for(auto key : { DomainProfile, StandardProfile, PublicProfile }) {
            RegistryKey allowedapps{ key, L"AuthorizedApplications\\List" };
            if(allowedapps.Exists()) {
                for(auto ProgramException : allowedapps.EnumerateValues()) {
                    CREATE_DETECTION(Certainty::Strong,
                                     RegistryDetectionData{ *RegistryValue::Create(allowedapps, ProgramException),
                                                            RegistryDetectionType::Configuration });
                    if(FileScanner::PerformQuickScan(ProgramException)) {
                        CREATE_DETECTION(Certainty::Weak, FileDetectionData{ ProgramException });
                    }
                }
            }

            auto ports = RegistryKey{ key, L"GloballyOpenPorts\\List" };
            if(ports.Exists()) {
                for(auto PortsException : ports.EnumerateValues()) {
                    CREATE_DETECTION(Certainty::Strong,
                                     RegistryDetectionData{ *RegistryValue::Create(ports, PortsException),
                                                            RegistryDetectionType::Configuration });
                }
            }
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1089::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events;

        Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE,
                                    L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\Do"
                                    L"mainProfile",
                                    false, false, true);
        Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE,
                                    L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\St"
                                    L"andardProfile",
                                    false, false, true);
        Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE,
                                    L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\Pu"
                                    L"blicProfile",
                                    false, false, true);

        return events;
    }
}   // namespace Hunts
