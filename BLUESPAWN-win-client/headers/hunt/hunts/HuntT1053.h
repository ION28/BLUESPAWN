#pragma once
#include "../Hunt.h"

namespace Hunts {

    /**
	 * HuntT1053 looks for malicious activity hidden in scheduled tasks/jobs
	 * T1053.005: examines Windows events for new scheduled tasks
	 * 
	 * @monitor Triggers a hunt whenever Security log event ID 4698/Task-Scheduler 106 is generated
	 */
    class HuntT1053 : public Hunt {

        public:
        HuntT1053();

        std::vector<EventLogs::EventLogItem> Get4698Events();
        std::vector<EventLogs::EventLogItem> Get106Events();

        void Subtechnique005(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections);

        virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
        virtual std::vector<std::pair<std::unique_ptr<Event>, Scope>> GetMonitoringEvents() override;
    };
}   // namespace Hunts
