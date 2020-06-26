#pragma once
#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1050 examines Windows events for new services created
	 *
	 * @monitor Triggers a hunt whenever System log event ID 7045 is generated
	 */
	class HuntT1050 : public Hunt {
	public:
		HuntT1050();

		std::vector<EventLogs::EventLogItem> Get7045Events();

		virtual std::vector<std::reference_wrapper<Detection>> RunHunt(const Scope& scope) override;
		virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
	};
}
