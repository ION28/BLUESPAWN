#pragma once
#include <Windows.h>

#include "../Hunt.h"

namespace Hunts {

	/**
	 * HuntT1103 examines AppInit DLLs related registry keys that can be used for
	 * persistence and privilege escalation.
	 */
	class HuntT1103 : public Hunt {
	public:
		HuntT1103();

		virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope);
		virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
	};
}