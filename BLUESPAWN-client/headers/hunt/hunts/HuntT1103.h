#pragma once
#include <Windows.h>

#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1004 examines AppInit DLLs related registry keys that can be used for
	 * persistence and privilege escalation.
	 */
	class HuntT1103 : public Hunt {
	public:
		HuntT1103();

		virtual std::vector<std::shared_ptr<DETECTION>> RunHunt(const Scope& scope);
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}