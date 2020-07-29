#pragma once
#include "../Hunt.h"

namespace Hunts {

    /**
	 * HuntT1136 examines Windows events for new accounts created
     * T1136.001: looks for local Windows accounts that were created
	 *
	 * @monitor Triggers a hunt whenever Security log event ID 4720 is generated
	 */
    class HuntT1136 : public Hunt {
        private:
        std::wstring t1136_001 = L"001: Local Account";

        public:
        HuntT1136();

        virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
        virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
    };
}   // namespace Hunts
#pragma once
