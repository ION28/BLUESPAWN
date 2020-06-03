#pragma once
#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1050 examines Windows events for new services created
	 *
	 * @scans Cursory Scan not supported.
	 * @scans Normal checks System logs for event id 7045 for new events
	 * @scans Intensive checks System logs for event id 7045 for new events
	 * @monitor Triggers a hunt whenever System log event ID 7045 is generated
	 */
	class HuntT1050 : public Hunt {
	public:
		HuntT1050();

		std::vector<EventLogs::EventLogItem> Get7045Events();

		virtual int ScanNormal(const Scope& scope, Reaction reaction) override;
		virtual int ScanIntensive(const Scope& scope, Reaction reaction) override;
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}
