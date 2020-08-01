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

        public:
        HuntT1553();

        void Subtechnique003(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections);

        virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
        virtual std::vector<std::pair<std::unique_ptr<Event>, Scope>> GetMonitoringEvents() override;
    };
}   // namespace Hunts
