#include "hunt/hunts/HuntT1050.h"

#include <iostream>
#include <set>

#include "common/StringUtils.h"
#include "common/Utils.h"

#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"
#include "util/processes/ProcessUtils.h"

#include "scan/ServiceScanner.h"
#include "scan/YaraScanner.h"
#include "user/bluespawn.h"

namespace Hunts {

    HuntT1050::HuntT1050() : Hunt(L"T1050 - New Service") {
        // TODO: update these categories
        dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
        dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
        dwTacticsUsed = (DWORD) Tactic::Persistence;
    }

    std::vector<EventLogs::EventLogItem> HuntT1050::Get7045Events() {
        // Create existance queries so interesting data is output
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

        return queryResults;
    }

    std::vector<std::reference_wrapper<Detection>> HuntT1050::RunHunt(const Scope& scope) {
        HUNT_INIT();

        auto queryResults = Get7045Events();

        for(auto result : queryResults) {
            auto imageName{ result.GetProperty(L"Event/EventData/Data[@Name='ServiceName']") };
            auto imagePath{ GetImagePathFromCommand(result.GetProperty(L"Event/EventData/Data[@Name='ImagePath']")) };

            FILETIME ft{};

            ULONGLONG time = (ULONGLONG) stoull(result.GetTimeCreated());
            ULONGLONG nano = 0;

            ft.dwHighDateTime = (DWORD)((time >> 32) & 0xFFFFFFFF);
            ft.dwLowDateTime = (DWORD)(time & 0xFFFFFFFF);

            auto malicious{ Certainty::None };

            if(imagePath.find(L"svchost.exe") != std::wstring::npos) {
                // svchost services are rarely if ever should have 7045 events
                malicious = malicious + Certainty::Strong;
            } else if(ServiceScanner::PerformQuickScan(std::nullopt, imageName, imagePath)) {
                malicious = malicious + Certainty::Moderate;
            }

            if(malicious > Certainty::None) {
                CREATE_DETECTION_WITH_CONTEXT(malicious, ServiceDetectionData{ std::nullopt, imageName, imagePath },
                                              DetectionContext{ GetName(), ft });
            }
        }

        HUNT_END();
    }

    std::vector<std::unique_ptr<Event>> HuntT1050::GetMonitoringEvents() {
        std::vector<std::unique_ptr<Event>> events;

        events.push_back(std::make_unique<EventLogEvent>(L"System", 7045));

        return events;
    }

}   // namespace Hunts
