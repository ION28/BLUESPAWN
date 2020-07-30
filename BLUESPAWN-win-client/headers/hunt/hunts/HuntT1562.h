#pragma once

#include "../Hunt.h"

namespace Hunts {

    /**
	 * HuntT1562 looks for ways attacks impair defenses. Currently examines the registry for firewall
	 * settings that allow applications to override the existing firewall rules.
	 */
    class HuntT1562 : public Hunt {
        private:
        std::wstring t1562_004 = L"004: Disable or Modify System Firewall";

        public:
        HuntT1562();

        virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
        virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
    };
}   // namespace Hunts
