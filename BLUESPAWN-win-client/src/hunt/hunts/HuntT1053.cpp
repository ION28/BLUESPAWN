#include "hunt/hunts/HuntT1053.h"

#include "common/Utils.h"

#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"

#include "scan/YaraScanner.h"
#include "user/bluespawn.h"

namespace Hunts {

    HuntT1053::HuntT1053() : Hunt(L"T1053 - Scheduled Task") {
        dwCategoriesAffected = (DWORD) Category::Files | (DWORD) Category::Processes;
        dwSourcesInvolved = (DWORD) DataSource::EventLogs;
        dwTacticsUsed = (DWORD) Tactic::Execution | (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
    }

    std::vector<EventLogs::EventLogItem> HuntT1053::Get4698Events() {
        // Create existance queries so interesting data is output
        std::vector<EventLogs::XpathQuery> queries;
        auto param1 = EventLogs::ParamList();
        auto param2 = EventLogs::ParamList();
        auto param3 = EventLogs::ParamList();
        auto param4 = EventLogs::ParamList();
        param1.push_back(std::make_pair(L"Name", L"'SubjectUserName'"));
        param2.push_back(std::make_pair(L"Name", L"'SubjectDomainName'"));
        param3.push_back(std::make_pair(L"Name", L"'TaskName'"));
        param4.push_back(std::make_pair(L"Name", L"'TaskContent'"));
        queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param1));
        queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param2));
        queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param3));
        queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param4));

        auto queryResults = EventLogs::QueryEvents(L"Security", 4698, queries);

        return queryResults;
    }

    std::vector<EventLogs::EventLogItem> HuntT1053::Get106Events() {
        // Create existance queries so interesting data is output
        std::vector<EventLogs::XpathQuery> queries;
        auto param1 = EventLogs::ParamList();
        auto param2 = EventLogs::ParamList();
        param1.push_back(std::make_pair(L"Name", L"'TaskName'"));
        param2.push_back(std::make_pair(L"Name", L"'UserContext'"));
        queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param1));
        queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param2));

        auto queryResults = EventLogs::QueryEvents(L"Microsoft-Windows-TaskScheduler/Operational", 106, queries);

        return queryResults;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1053::RunHunt(const Scope& scope) {
        HUNT_INIT();

        auto queryResults = Get4698Events();
        auto queryResults2 = Get106Events();

        // clang-format off
        for(auto result : queryResults) {
            CREATE_DETECTION(Certainty::Moderate, OtherDetectionData{ L"Scheduled Task", {
                { L"Name", result.GetProperty(L"Event/EventData/Data[@Name='TaskName']") },
                { L"User", result.GetProperty(L"Event/EventData/Data[@Name='SubjectUserName']") },
                { L"Content", result.GetProperty(L"Event/EventData/Data[@Name='TaskContent']") }
            }});
		}

		for (auto result : queryResults2) {
            CREATE_DETECTION(Certainty::Moderate, OtherDetectionData{ L"Scheduled Task", {
                { L"Name", result.GetProperty(L"Event/EventData/Data[@Name='TaskName']") },
                { L"User", result.GetProperty(L"Event/EventData/Data[@Name='SubjectUserName']") }
            }});
		}
        // clang-format on

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1053::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events;

        events.push_back(std::make_unique<EventLogEvent>(L"Security", 4698));
        events.push_back(std::make_unique<EventLogEvent>(L"Microsoft-Windows-TaskScheduler/Operational", 106));

        return events;
    }
}   // namespace Hunts
