#include "hunt/hunts/HuntT1070.h"

#include <iostream>

#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"
#include "util/processes/ProcessUtils.h"

#include "user/bluespawn.h"

#define TIMESTOMP 0

namespace Hunts {

    HuntT1070::HuntT1070() : Hunt(L"T1070 - Indicator Removal on Host") {
        dwCategoriesAffected = (DWORD) Category::Files | (DWORD) Category::Processes;
        dwSourcesInvolved = (DWORD) DataSource::EventLogs;
        dwTacticsUsed = (DWORD) Tactic::DefenseEvasion;
    }

    void HuntT1070::Subtechnique006(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections){
        SUBTECHNIQUE_INIT(006, Timestomp);

        SUBSECTION_INIT(TIMESTOMP, Normal);
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
        for(auto query : queryResults){
            FileSystem::File file{ query.GetProperty(L"Event/EventData/Data[@Name='TargetFilename']") };
            CREATE_DETECTION(Certainty::Strong, FileDetectionData{ file });

            // Scan process
            HandleWrapper hProcess{ 
                OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false,
                            std::stoi(query.GetProperty(L"Event/EventData/Data[@Name='ProcessId']"))) };
            if(hProcess){
                auto image{ GetProcessImage(hProcess) };
                CREATE_DETECTION(Certainty::Moderate,
                                 ProcessDetectionData::CreateProcessDetectionData(GetProcessId(hProcess), image));
            }
        }
        SUBSECTION_END();

        SUBTECHNIQUE_END();
    }

    std::vector<std::shared_ptr<Detection>> HuntT1070::RunHunt(const Scope& scope) {
        HUNT_INIT();

        Subtechnique006(scope, detections);

        HUNT_END();
    }

    std::vector<std::pair<std::unique_ptr<Event>, Scope>> HuntT1070::GetMonitoringEvents() {
        std::vector<std::pair<std::unique_ptr<Event>, Scope>> events{};

        events.push_back(std::make_pair(std::make_unique<EventLogEvent>(L"Microsoft-Windows-Sysmon/Operational", 2), 
                                        SCOPE(TIMESTOMP)));

        return events;
    }
}   // namespace Hunts
