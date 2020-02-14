#pragma once
#include "../Hunt.h"
#include "hunt/reaction/Reaction.h"
#include "hunt/reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1050 examines Windows events for new services created
	 *
	 * @scans Cursory checks System logs for event id 7045 for new events
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 * @monitor Triggers a hunt whenever System log event ID 7045 is generated
	 */
	class HuntT1050 : public Hunt {
	public:
		HuntT1050();

		virtual int ScanNormal(const Scope& scope, Reaction reaction) override;
		virtual int ScanIntensive(const Scope& scope, Reaction reaction) override;
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}
