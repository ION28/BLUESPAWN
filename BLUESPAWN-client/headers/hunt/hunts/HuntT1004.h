#pragma once
#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1004 examines Winlogon related registry keys that can be used for
	 * persistence.
	 */
	class HuntT1004 : public Hunt {
	public:
		HuntT1004();

		virtual std::vector<std::shared_ptr<DETECTION>> RunHunt(const Scope& scope) override;
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}