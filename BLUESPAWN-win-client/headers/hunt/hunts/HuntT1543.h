#pragma once
#include "../Hunt.h"

namespace Hunts {

    /**
	 * HuntT1543 examines system services for evidence of bad.
     * T1543.003: examines Windows events for new services created
	 *
	 * @monitor Triggers a hunt whenever System log event ID 7045 is generated
	 */
    class HuntT1543 : public Hunt {

        public:
        HuntT1543();

        void Subtechnique003(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections);

        virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
        virtual std::vector<std::pair<std::unique_ptr<Event>, Scope>> GetMonitoringEvents() override;
    };
}   // namespace Hunts
