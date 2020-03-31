#pragma once
#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1138 examines the system for the presence of Application Shimming that can
	 * be used for persistence and privilege escalation.
	 */
	class HuntT1138 : public Hunt {
	public:
		HuntT1138();

		virtual std::vector<std::shared_ptr<DETECTION>> RunHunt(const Scope& scope);
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}