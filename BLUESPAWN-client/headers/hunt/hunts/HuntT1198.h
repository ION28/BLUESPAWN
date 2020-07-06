#pragma once

#include "../Hunt.h"

namespace Hunts{

	/**
	 * HuntT1198 examines Subject Interface Providers and Trust Providers, which can
	 * be used by malicious actors to cause malicious payloads to appear signed, and
	 * establish persistence
	 */
	class HuntT1198 : public Hunt {
	public:
		HuntT1198();

		virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
		virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
	};
}