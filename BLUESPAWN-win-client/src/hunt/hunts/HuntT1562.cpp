#include "hunt/hunts/HuntT1562.h"

#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"

#include "scan/FileScanner.h"
#include "user/bluespawn.h"

using namespace Registry;

namespace Hunts {

    HuntT1562::HuntT1562() : Hunt(L"T1562 - Impair Defenses") {
        dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Network;
        dwSourcesInvolved = (DWORD) DataSource::Registry;
        dwTacticsUsed = (DWORD) Tactic::DefenseEvasion;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1562::RunHunt(const Scope& scope) {
        HUNT_INIT();

        // Looks for T1562.004: Disable or Modify System Firewall
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
                    CREATE_DETECTION_WITH_CONTEXT(
                        Certainty::Strong,
                        RegistryDetectionData{ *RegistryValue::Create(allowedapps, ProgramException),
                                               RegistryDetectionType::Configuration },
                        DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1562_004) });
                    if(FileScanner::PerformQuickScan(ProgramException)) {
                        CREATE_DETECTION(Certainty::Weak, FileDetectionData{ ProgramException });
                    }
                }
            }

            auto ports = RegistryKey{ key, L"GloballyOpenPorts\\List" };
            if(ports.Exists()) {
                for(auto PortsException : ports.EnumerateValues()) {
                    CREATE_DETECTION_WITH_CONTEXT(Certainty::Strong,
                                                  RegistryDetectionData{ *RegistryValue::Create(ports, PortsException),
                                                                         RegistryDetectionType::Configuration },
                                                  DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1562_004) });
                }
            }
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1562::GetMonitoringEvents() {
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
