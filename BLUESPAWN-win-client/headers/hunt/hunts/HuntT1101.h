#pragma once
#include <Windows.h>

#include <unordered_set>

#include "../Hunt.h"

namespace Hunts {

	/**
	 * HuntT1101 examines Security Support Providers (SSPs) on the system
	 */
	class HuntT1101 : public Hunt {
	public:
		HuntT1101();

		virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope);
		virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
	};
}
