#include "hunt/hunts/HuntT1543.h"

#include <iostream>
#include <set>

#include "util/StringUtils.h"
#include "util/Utils.h"
#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"
#include "util/processes/ProcessUtils.h"

#include "hunt/RegistryHunt.h"
#include "scan/FileScanner.h"
#include "scan/ProcessScanner.h"
#include "scan/ServiceScanner.h"
#include "scan/YaraScanner.h"
#include "user/bluespawn.h"

using namespace Registry;

#define DNS_SECTION 0
#define NTDS_SECTION 1
#define WINSOCK_PARAMS 2
#define WINSOCK_CATALOG 3
#define WINSOCK_CUR_CATALOG 4
#define FAILURE_SECTION 5
#define LOGS_SECTION 6

namespace Hunts {

    HuntT1543::HuntT1543() : Hunt(L"T1543 - Create or Modify System Process") {
        dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
        dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem |
                            (DWORD) DataSource::EventLogs;
        dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
    }

    void HuntT1543::Subtechnique003(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections) {
        SUBTECHNIQUE_INIT(003, Windows Service);

        // DNS Service Audit
        SUBSECTION_INIT(DNS_SECTION, Cursory);
        for(auto& detection : CheckValues(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\DNS\\Parameters",
                                          {
                                              { L"ServerLevelPluginDll", L"", false, CheckSzEmpty },
                                          },
                                          false, false)) {
            CREATE_DETECTION(Certainty::Strong,
                             RegistryDetectionData{ detection, RegistryDetectionType::FileReference });
        }
        SUBSECTION_END();

        // NTDS Service Audit
        SUBSECTION_INIT(NTDS_SECTION, Cursory);
        for(auto& detection : CheckValues(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\NTDS",
                                          {
                                              { L"LsaDbExtPt", L"", false, CheckSzEmpty },
                                              { L"DirectoryServiceExtPt", L"", false, CheckSzEmpty },
                                          },
                                          false, false)) {
            CREATE_DETECTION(Certainty::Moderate,
                             RegistryDetectionData{ detection, RegistryDetectionType::FileReference });
        }
        SUBSECTION_END();

        // Winsock2 Service Audit
        auto winsock2 = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters" };
        SUBSECTION_INIT(WINSOCK_PARAMS, Cursory);
        for(auto paramdll : { L"AutodialDLL", L"NameSpace_Callout" }) {
            auto detection{ Registry::RegistryValue::Create(winsock2, paramdll) };
            if(detection && FileScanner::PerformQuickScan(detection->ToString())) {
                CREATE_DETECTION(Certainty::Moderate,
                                 RegistryDetectionData{ *detection, RegistryDetectionType::FileReference });
            }
        }
        SUBSECTION_END();

        SUBSECTION_INIT(WINSOCK_CATALOG, Cursory);
        auto appids = RegistryKey{ winsock2, L"AppId_Catalog" };
        for(auto subkey : appids.EnumerateSubkeys()) {
            auto detection{ Registry::RegistryValue::Create(winsock2, L"AppFullPath") };
            if(detection && FileScanner::PerformQuickScan(detection->ToString())) {
                CREATE_DETECTION(Certainty::Moderate,
                                 RegistryDetectionData{ *detection, RegistryDetectionType::FileReference });
            }
        }
        SUBSECTION_END();

        SUBSECTION_INIT(WINSOCK_CUR_CATALOG, Cursory);
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
        SUBSECTION_END();

        // Service Failure Audit
        SUBSECTION_INIT(FAILURE_SECTION, Normal);
        auto services = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services" };
        for(auto service : services.EnumerateSubkeys()) {
            auto detection{ Registry::RegistryValue::Create(service, L"FailureCommand") };
            if(detection && ProcessScanner::PerformQuickScan(detection->ToString())) {
                CREATE_DETECTION(Certainty::Moderate,
                                 RegistryDetectionData{ *detection, RegistryDetectionType::CommandReference });
            }
        }
        SUBSECTION_END();

        // Looks for 7045 New Service Created events
        SUBSECTION_INIT(LOGS_SECTION, Normal);
        std::vector<EventLogs::XpathQuery> queries;
        auto param1 = EventLogs::ParamList();
        auto param2 = EventLogs::ParamList();
        auto param3 = EventLogs::ParamList();
        auto param4 = EventLogs::ParamList();
        param1.push_back(std::make_pair(L"Name", L"'ServiceName'"));
        param2.push_back(std::make_pair(L"Name", L"'ImagePath'"));
        param3.push_back(std::make_pair(L"Name", L"'ServiceType'"));
        param4.push_back(std::make_pair(L"Name", L"'StartType'"));
        queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param1));
        queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param2));
        queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param3));
        queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param4));

        auto queryResults = EventLogs::QueryEvents(L"System", 7045, queries);

        for(auto result : queryResults) {
            auto imageName{ result.GetProperty(L"Event/EventData/Data[@Name='ServiceName']") };
            auto imagePath{ GetImagePathFromCommand(result.GetProperty(L"Event/EventData/Data[@Name='ImagePath']")) };

            FILETIME ft{};

            ULONGLONG time = (ULONGLONG) stoull(result.GetTimeCreated());
            ULONGLONG nano = 0;

            ft.dwHighDateTime = (DWORD)((time >> 32) & 0xFFFFFFFF);
            ft.dwLowDateTime = (DWORD)(time & 0xFFFFFFFF);

            auto malicious{ Certainty::None };

            bool svchost{ false };
            if(imagePath.find(L"svchost.exe") != std::wstring::npos) {
                // svchost services are rarely if ever should have 7045 events
                malicious = malicious + Certainty::Weak;
                svchost = true;
            } else if(ServiceScanner::PerformQuickScan(std::nullopt, imageName, imagePath)) {
                malicious = malicious + Certainty::Moderate;
            }

            if(malicious > Certainty::None) {
                // clang-format off
                CREATE_DETECTION_WITH_CONTEXT(
                    malicious, ServiceDetectionData{ std::nullopt, imageName, imagePath },
                    DetectionContext{ __name, ft, svchost ? std::optional<std::wstring>{
                    L"Most if not all svchost services should come preinstalled and therefore should not show up in "
                    "the event logs. However, this can sometimes happen legitimately" } : std::nullopt });
                // clang-format on
            }
        }
        SUBSECTION_END();

        SUBTECHNIQUE_END();
    }

    std::vector<std::shared_ptr<Detection>> HuntT1543::RunHunt(const Scope& scope) {
        HUNT_INIT();

        Subtechnique003(scope, detections);

        HUNT_END();
    }

    std::vector<std::pair<std::unique_ptr<Event>, Scope>> HuntT1543::GetMonitoringEvents() {
        std::vector<std::pair<std::unique_ptr<Event>, Scope>> events;

        // Looks for T1543.003: Windows Service
        GetRegistryEvents(events, SCOPE(FAILURE_SECTION), HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services",
                          false, false);
        GetRegistryEvents(events, SCOPE(NTDS_SECTION), HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\NTDS",
                          false, false);
        GetRegistryEvents(events, SCOPE(DNS_SECTION), HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Services\\DNS\\Parameters", false, false);
        GetRegistryEvents(events, Scope::CreateSubhuntScope((1 << WINSOCK_PARAMS) | (1 << WINSOCK_CUR_CATALOG)),
                          HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters", false,
                          false, true);
        GetRegistryEvents(events, SCOPE(WINSOCK_CATALOG), HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\AppId_Catalog", false, false);
        events.push_back(std::make_pair(std::make_unique<EventLogEvent>(L"System", 7045), SCOPE(LOGS_SECTION)));

        return events;
    }

}   // namespace Hunts
