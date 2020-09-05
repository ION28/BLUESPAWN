#pragma once
#include "../Hunt.h"

namespace Hunts {

    /**
	 * HuntT1070 looks for evidence attackers tried to cover their tracks.
	 * Currently examines Sysmon logs looking for timestomp events
	 *
	 * @monitor Triggers a hunt whenever Sysmon log event ID 2 is generated
	 */
    class HuntT1070 : public Hunt {

        public:
        HuntT1070();

        void Subtechnique006(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections);

        virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
        virtual std::vector<std::pair<std::unique_ptr<Event>, Scope>> GetMonitoringEvents() override;
    };
}   // namespace Hunts
