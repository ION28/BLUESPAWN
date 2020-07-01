#include "hunt/hunts/HuntT1099.h"

#include <iostream>

#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"

#include "scan/YaraScanner.h"
#include "user/bluespawn.h"

namespace Hunts {

    HuntT1099::HuntT1099() : Hunt(L"T1099 - Timestomp") {
        dwCategoriesAffected = (DWORD) Category::Files | (DWORD) Category::Processes;
        dwSourcesInvolved = (DWORD) DataSource::EventLogs;
        dwTacticsUsed = (DWORD) Tactic::DefenseEvasion;
    }

    std::vector<std::reference_wrapper<Detection>> HuntT1099::RunHunt(const Scope& scope) {
        HUNT_INIT();

        // Create existance queries so interesting data is output
        std::vector<EventLogs::XpathQuery> queries;
        auto param1 = EventLogs::ParamList();
        auto param2 = EventLogs::ParamList();
        auto param3 = EventLogs::ParamList();
        auto param4 = EventLogs::ParamList();
        auto param5 = EventLogs::ParamList();
        param1.push_back(std::make_pair(L"Name", L"'Image'"));
        param2.push_back(std::make_pair(L"Name", L"'ProcessId'"));
        param3.push_back(std::make_pair(L"Name", L"'TargetFilename'"));
        param4.push_back(std::make_pair(L"Name", L"'CreationUtcTime'"));
        param5.push_back(std::make_pair(L"Name", L"'PreviousCreationUtcTime'"));
        queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param1));
        queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param2));
        queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param3));
        queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param4));
        queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param5));

        auto queryResults = EventLogs::QueryEvents(L"Microsoft-Windows-Sysmon/Operational", 2, queries);

        // Find detections with YARA rules
        for(auto query : queryResults) {
            FileSystem::File file = FileSystem::File(query.GetProperty(L"Event/EventData/"
                                                                       L"Data[@Name='TargetFilename']"));
            CREATE_DETECTION(Certainty::Strong, FileDetectionData{ file });

            // Scan process?
            /* HandleWrapper hProcess{ OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, std::stoi(query.GetProperty(L"Event/EventData/Data[@Name='ProcessId']"))) };
			if(hProcess){
				
			} */
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1099::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events{};

        events.push_back(std::make_unique<EventLogEvent>(L"Microsoft-Windows-Sysmon/Operational", 2));

        return events;
    }
}   // namespace Hunts
