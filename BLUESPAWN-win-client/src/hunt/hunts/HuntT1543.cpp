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

namespace Hunts {

    HuntT1543::HuntT1543() : Hunt(L"T1543 - Create or Modify System Process") {
        dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
        dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem |
                            (DWORD) DataSource::EventLogs;
        dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1543::RunHunt(const Scope& scope) {
        HUNT_INIT();

        // Looks for T1543.003: Windows Service
        // DNS Service Audit
        for(auto& detection : CheckValues(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\DNS\\Parameters",
                                          {
                                              { L"ServerLevelPluginDll", L"", false, CheckSzEmpty },
                                          },
                                          false, false)) {
            CREATE_DETECTION_WITH_CONTEXT(Certainty::Strong,
                                          RegistryDetectionData{ detection, RegistryDetectionType::FileReference },
                                          DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1543_003) });
        }

        // NTDS Service Audit
        for(auto& detection : CheckValues(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\NTDS",
                                          {
                                              { L"LsaDbExtPt", L"", false, CheckSzEmpty },
                                              { L"DirectoryServiceExtPt", L"", false, CheckSzEmpty },
                                          },
                                          false, false)) {
            CREATE_DETECTION_WITH_CONTEXT(Certainty::Moderate,
                                          RegistryDetectionData{ detection, RegistryDetectionType::FileReference },
                                          DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1543_003) });
        }

        // Winsock2 Service Audit
        auto winsock2 = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters" };
        for(auto paramdll : { L"AutodialDLL", L"NameSpace_Callout" }) {
            auto detection{ Registry::RegistryValue::Create(winsock2, paramdll) };
            if(detection && FileScanner::PerformQuickScan(detection->ToString())) {
                CREATE_DETECTION_WITH_CONTEXT(Certainty::Moderate,
                                              RegistryDetectionData{ *detection, RegistryDetectionType::FileReference },
                                              DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1543_003) });
            }
        }

        auto appids = RegistryKey{ winsock2, L"AppId_Catalog" };
        for(auto subkey : appids.EnumerateSubkeys()) {
            auto detection{ Registry::RegistryValue::Create(winsock2, L"AppFullPath") };
            if(detection && FileScanner::PerformQuickScan(detection->ToString())) {
                CREATE_DETECTION_WITH_CONTEXT(Certainty::Moderate,
                                              RegistryDetectionData{ *detection, RegistryDetectionType::FileReference },
                                              DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1543_003) });
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
                        CREATE_DETECTION_WITH_CONTEXT(Certainty::Moderate,
                                                      RegistryDetectionData{ *detection,
                                                                             RegistryDetectionType::FileReference },
                                                      DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1543_003) });
                    }
                }
            }
        }

        // Service Failure Audit
        auto services = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services" };
        for(auto service : services.EnumerateSubkeys()) {
            auto detection{ Registry::RegistryValue::Create(service, L"FailureCommand") };
            if(detection && ProcessScanner::PerformQuickScan(detection->ToString())) {
                CREATE_DETECTION_WITH_CONTEXT(
                    Certainty::Moderate, RegistryDetectionData{ *detection, RegistryDetectionType::CommandReference },
                    DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1543_003) });
            }
        }

        // Looks for 7045 New Service Created events
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
                malicious = malicious + Certainty::Strong;
                svchost = true;
            } else if(ServiceScanner::PerformQuickScan(std::nullopt, imageName, imagePath)) {
                malicious = malicious + Certainty::Moderate;
            }

            if(malicious > Certainty::None) {
                // clang-format off
                CREATE_DETECTION_WITH_CONTEXT(
                    malicious, ServiceDetectionData{ std::nullopt, imageName, imagePath },
                    DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1543_003), ft, svchost ? std::optional<std::wstring>{ 
                    L"Most if not all svchost services should come preinstalled and therefore should not show up in "
                    "the event logs. However, this can sometimes happen legitimately" } : std::nullopt });
                // clang-format on
            }
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1543::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events;

        // Looks for T1543.003: Windows Service
        GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", false, false);
        GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\NTDS", false, false);
        GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\DNS\\Parameters", false,
                          false);
        GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters",
                          false, false, true);
        events.push_back(std::make_unique<EventLogEvent>(L"System", 7045));

        return events;
    }

}   // namespace Hunts
