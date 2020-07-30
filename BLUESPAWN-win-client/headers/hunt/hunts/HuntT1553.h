#pragma once

#include "../Hunt.h"

namespace Hunts {

    /**
	 * HuntT1553 looks for attackers blending in by abusing trust on the system.
     * T1553.003: examines Subject Interface Providers and Trust Providers, which can
	 * be used by malicious actors to cause malicious payloads to appear signed, and
	 * establish persistence
	 */
    class HuntT1553 : public Hunt {
        private:
        std::wstring t1553_003 = L"003: SIP and Trust Provider Hijacking";

        public:
        HuntT1553();

        virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
        virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
    };
}   // namespace Hunts
