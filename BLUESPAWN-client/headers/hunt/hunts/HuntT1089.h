#pragma once

#include "../Hunt.h"

namespace Hunts {

	/**
	 * HuntT1089 examines the registry for firewall settings that allow
	 * applications to override the existing firewall rules.
	 */
	class HuntT1089 : public Hunt {
	public:
		HuntT1089();

		virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
		virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
	};
}