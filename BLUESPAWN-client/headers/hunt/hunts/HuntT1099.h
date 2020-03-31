#pragma once
#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1099 examines Sysmon logs looking for timestomp events
	 *
	 * @monitor Triggers a hunt whenever Sysmon log event ID 2 is generated
	 */
	class HuntT1099 : public Hunt {
	public:
		HuntT1099();

		virtual std::vector<std::shared_ptr<DETECTION>> RunHunt(const Scope& scope) override;
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}
