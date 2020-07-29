#include "hunt/hunts/HuntT1070.h"

#include <iostream>

#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"
#include "util/processes/ProcessUtils.h"

#include "user/bluespawn.h"

namespace Hunts {

    HuntT1070::HuntT1070() : Hunt(L"T1070 - Indicator Removal on Host") {
        dwCategoriesAffected = (DWORD) Category::Files | (DWORD) Category::Processes;
        dwSourcesInvolved = (DWORD) DataSource::EventLogs;
        dwTacticsUsed = (DWORD) Tactic::DefenseEvasion;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1070::RunHunt(const Scope& scope) {
        HUNT_INIT();

        // Looks for T1070.006 Timestomp
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
            CREATE_DETECTION_WITH_CONTEXT(Certainty::Strong, FileDetectionData{ file },
                                          DetectionContext{ ADD_SUBTECHNIQUE_CONTEXT(t1070_006) });

            // Scan process
            HandleWrapper hProcess{ OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false,
                                                std::stoi(query.GetProperty(L"Event/EventData/"
                                                                            L"Data[@Name='ProcessId']"))) };
            if(hProcess) {
                auto image{ GetProcessImage(hProcess) };
                CREATE_DETECTION(Certainty::Moderate,
                                 ProcessDetectionData::CreateProcessDetectionData(GetProcessId(hProcess), image));
            }
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1070::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events{};

        events.push_back(std::make_unique<EventLogEvent>(L"Microsoft-Windows-Sysmon/Operational", 2));

        return events;
    }
}   // namespace Hunts
