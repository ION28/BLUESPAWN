#pragma once
#include "../Hunt.h"

namespace Hunts {

	/**
	 * HuntT1053 examines Windows events for new scheduled tasks
	 * 
	 * @monitor Triggers a hunt whenever Security log event ID 4698/Task-Scheduler 106 is generated
	 */
	class HuntT1053 : public Hunt {
	public:
		HuntT1053();

		std::vector<EventLogs::EventLogItem> Get4698Events();
		std::vector<EventLogs::EventLogItem> Get106Events();

		virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
		virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
	};
}
