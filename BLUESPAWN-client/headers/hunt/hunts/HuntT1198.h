#pragma once

#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts{

	/**
	 * HuntT1198 examines Subject Interface Providers and Trust Providers, which can
	 * be used by malicious actors to cause malicious payloads to appear signed, and
	 * establish persistence
	 *
	 * @scans Cursory Scan not supported.
	 * @scans Normal Scans SIPs and trust providers and ensures they are valid.
	 * @scans Intensive Scan not supported.
	 */
	class HuntT1198 : public Hunt {
	public:
		HuntT1198();

		virtual int ScanNormal(const Scope& scope, Reaction reaction) override;
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}