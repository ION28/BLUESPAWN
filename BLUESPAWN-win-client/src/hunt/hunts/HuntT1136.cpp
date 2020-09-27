#include "hunt/hunts/HuntT1136.h"

#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"

#include "user/bluespawn.h"

#define USER_LOG 0
#define HIDDEN_USER 1

namespace Hunts {

    HuntT1136::HuntT1136() : Hunt(L"T1136 - Create Account") {
        dwCategoriesAffected = (DWORD) Category::Configurations;
        dwSourcesInvolved = (DWORD) DataSource::EventLogs;
        dwTacticsUsed = (DWORD) Tactic::Persistence;
    }

    void HuntT1136::Subtechnique001(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections){
        SUBTECHNIQUE_INIT(001, Local Account);

        SUBSECTION_INIT(USER_LOG, Normal);

        // Looks for T1136.001: Local Account
        // Create existance queries so interesting data is output
        std::vector<EventLogs::XpathQuery> queries;
        auto param1 = EventLogs::ParamList();
        auto param2 = EventLogs::ParamList();
        param1.push_back(std::make_pair(L"Name", L"'TargetUserName'"));
        param2.push_back(std::make_pair(L"Name", L"'SubjectUserName'"));
        queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param1));
        queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param2));

        auto results = EventLogs::QueryEvents(L"Security", 4720, queries);
        for(auto result : results){
            // clang-format off
            CREATE_DETECTION(Certainty::None, OtherDetectionData{ L"User", {
                { L"Username", result.GetProperty(L"Event/EventData/Data[@Name='TargetUserName']") },
                { L"Creator", result.GetProperty(L"Event/EventData/Data[@Name='SubjectUserName']") }
            }});
            // clang-format on
        }
        SUBSECTION_END();

        SUBSECTION_INIT(HIDDEN_USER, Cursory);

        Permissions::User uHiddenUser(L"$");

        if (uHiddenUser.Exists()) {
            CREATE_DETECTION(Certainty::Certain, OtherDetectionData{ L"User", {
                { L"Username", L"$" },
                { L"Context", L"Users with this name are hidden from net user command."}
            }});
        }

        SUBSECTION_END();

        SUBTECHNIQUE_END();
    }

    std::vector<std::shared_ptr<Detection>> HuntT1136::RunHunt(const Scope& scope) {
        HUNT_INIT();

        Subtechnique001(scope, detections);

        HUNT_END();
    }

    std::vector<std::pair<std::unique_ptr<Event>, Scope>> HuntT1136::GetMonitoringEvents() {
        std::vector<std::pair<std::unique_ptr<Event>, Scope>> events;

        // Looks for T1136.001: Local Account
        events.push_back(std::make_pair(std::make_unique<EventLogEvent>(L"Security", 4720), SCOPE(USER_LOG)));

        return events;
    }
}   // namespace Hunts
