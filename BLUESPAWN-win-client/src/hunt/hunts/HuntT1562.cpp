#include "hunt/hunts/HuntT1562.h"

#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"

#include "scan/FileScanner.h"
#include "user/bluespawn.h"

using namespace Registry;

#define REGISTRY_FIREWALL 0

namespace Hunts {

    HuntT1562::HuntT1562() : Hunt(L"T1562 - Impair Defenses") {
        dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Network;
        dwSourcesInvolved = (DWORD) DataSource::Registry;
        dwTacticsUsed = (DWORD) Tactic::DefenseEvasion;
    }

    void HuntT1562::Subtechnique004(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections) {
        SUBTECHNIQUE_INIT(004, Disable or Modify System Firewall);

        SUBSECTION_INIT(REGISTRY_FIREWALL, Normal);
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
        SUBSECTION_END();

        SUBTECHNIQUE_END();
    }

    std::vector<std::shared_ptr<Detection>> HuntT1562::RunHunt(const Scope& scope) {
        HUNT_INIT();

        Subtechnique004(scope, detections);

        HUNT_END();
    }

    std::vector<std::pair<std::unique_ptr<Event>, Scope>> HuntT1562::GetMonitoringEvents() {
        std::vector<std::pair<std::unique_ptr<Event>, Scope>> events;

        Registry::GetRegistryEvents(events, SCOPE(REGISTRY_FIREWALL), HKEY_LOCAL_MACHINE,
                                    L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\Do"
                                    L"mainProfile",
                                    false, false, true);
        Registry::GetRegistryEvents(events, SCOPE(REGISTRY_FIREWALL), HKEY_LOCAL_MACHINE,
                                    L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\St"
                                    L"andardProfile",
                                    false, false, true);
        Registry::GetRegistryEvents(events, SCOPE(REGISTRY_FIREWALL), HKEY_LOCAL_MACHINE,
                                    L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\Pu"
                                    L"blicProfile",
                                    false, false, true);

        return events;
    }
}   // namespace Hunts
