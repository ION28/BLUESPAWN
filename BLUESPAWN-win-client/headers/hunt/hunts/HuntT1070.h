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
        private:
        std::wstring t1070_006 = L"006: Timestomp";

        public:
        HuntT1070();

        virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
        virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
    };
}   // namespace Hunts
