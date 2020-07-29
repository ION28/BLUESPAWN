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
        private:
        std::wstring t1543_003 = L"003: Windows Service";

        public:
        HuntT1543();

        virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
        virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
    };
}   // namespace Hunts
