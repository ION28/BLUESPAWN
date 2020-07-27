#include "hunt/hunts/HuntT1031.h"

#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"
#include "util/processes/CheckLolbin.h"

#include "hunt/RegistryHunt.h"
#include "scan/FileScanner.h"
#include "scan/ProcessScanner.h"
#include "user/bluespawn.h"

using namespace Registry;

namespace Hunts {

    HuntT1031::HuntT1031() : Hunt(L"T1031 - Modify Existing Service") {
        dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
        dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::Services;
        dwTacticsUsed = (DWORD) Tactic::Persistence;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1031::RunHunt(const Scope& scope) {
        HUNT_INIT();

        // DNS Service Audit
        for(auto& detection : CheckValues(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\DNS\\Parameters",{
                                              { L"ServerLevelPluginDll", L"", false, CheckSzEmpty },
                                          }, false, false)) {
            CREATE_DETECTION(Certainty::Strong,
                             RegistryDetectionData{ detection, RegistryDetectionType::FileReference });
        }

        // NTDS Service Audit
        for(auto& detection : CheckValues(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\NTDS", {
                                              { L"LsaDbExtPt", L"", false, CheckSzEmpty },
                                              { L"DirectoryServiceExtPt", L"", false, CheckSzEmpty },
                                          }, false, false)) {
            CREATE_DETECTION(Certainty::Moderate,
                             RegistryDetectionData{ detection, RegistryDetectionType::FileReference });
        }

        // Winsock2 Service Audit
        auto winsock2 = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters" };
        for(auto paramdll : { L"AutodialDLL", L"NameSpace_Callout" }) {
            auto detection{ Registry::RegistryValue::Create(winsock2, paramdll) };
            if(detection && FileScanner::PerformQuickScan(detection->ToString())) {
                CREATE_DETECTION(Certainty::Moderate,
                                 RegistryDetectionData{ *detection, RegistryDetectionType::FileReference });
            }
        }

        auto appids = RegistryKey{ winsock2, L"AppId_Catalog" };
        for(auto subkey : appids.EnumerateSubkeys()) {
            auto detection{ Registry::RegistryValue::Create(winsock2, L"AppFullPath") };
            if(detection && FileScanner::PerformQuickScan(detection->ToString())) {
                CREATE_DETECTION(Certainty::Moderate,
                                 RegistryDetectionData{ *detection, RegistryDetectionType::FileReference });
            }
        }

        auto currentCallout = winsock2.GetValue<std::wstring>(L"Current_NameSpace_Catalog");
        if(currentCallout) {
            auto namespaceCatalog = RegistryKey{ winsock2, currentCallout.value() + L"\\Catalog_Entries" };
            auto namespaceCatalog64 = RegistryKey{ winsock2, currentCallout.value() + L"\\Catalog_Entries64" };
            for(auto subkey : { namespaceCatalog, namespaceCatalog64 }) {
                for(auto entry : subkey.EnumerateSubkeys()) {
                    auto detection{ Registry::RegistryValue::Create(winsock2, L"LibraryPath") };
                    if(detection && FileScanner::PerformQuickScan(detection->ToString())) {
                        CREATE_DETECTION(Certainty::Moderate,
                                         RegistryDetectionData{ *detection, RegistryDetectionType::FileReference });
                    }
                }
            }
        }

        // Service Failure Audit
        auto services = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services" };
        for(auto service : services.EnumerateSubkeys()) {
            auto detection{ Registry::RegistryValue::Create(service, L"FailureCommand") };
            if(detection && ProcessScanner::PerformQuickScan(detection->ToString())) {
                CREATE_DETECTION(Certainty::Moderate,
                                 RegistryDetectionData{ *detection, RegistryDetectionType::CommandReference });
            }
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1031::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events;

        Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", false, false);
        Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\NTDS", false,
                                    false);
        Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\DNS\\Parameters",
                                    false, false);
        Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE,
                                    L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters", false, false, true);

        return events;
    }
}   // namespace Hunts
