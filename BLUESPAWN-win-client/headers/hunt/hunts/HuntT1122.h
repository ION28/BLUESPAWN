#pragma once

#include "../Hunt.h"

namespace Hunts{

	/**
	 * HuntT1122 examines CLSID registry values to detect COM hijacking, used in
	 * persistence.
	 */
	class HuntT1122 : public Hunt {
	public:
		HuntT1122();

		virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
		virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
	};
}