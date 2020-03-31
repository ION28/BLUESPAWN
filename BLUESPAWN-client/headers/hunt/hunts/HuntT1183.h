#pragma once

#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts{

	/**
	 * HuntT1183 examines the Image File Execution Options for debuggers and silent
	 * process exit hooks
	 */
	class HuntT1183 : public Hunt {
	public:
		HuntT1183();

		virtual std::vector<std::shared_ptr<DETECTION>> RunHunt(const Scope& scope);
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}