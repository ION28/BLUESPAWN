#pragma once
#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1053 examines Windows events for new scheduled tasks
	 *
	 * @scans Cursory Scan not supported.
	 * @scans Normal Scan not supported.
	 * @scans Intensive Security Logs for a 4698 and Task-Scheduler for a 106
	 * @monitor Triggers a hunt whenever Security log event ID 4698/Task-Scheduler 106 is generated
	 */
	class HuntT1053 : public Hunt {
	public:
		HuntT1053();

		std::vector<EventLogs::EventLogItem> Get4698Events();
		std::vector<EventLogs::EventLogItem> Get106Events();

		virtual int ScanIntensive(const Scope& scope, Reaction reaction) override;
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}
