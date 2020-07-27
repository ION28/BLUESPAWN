#pragma once

#include "../Hunt.h"

namespace Hunts {

	/**
	 * HuntT1128 examines the registry for bad Netsh Helper DLLs
	 */
	class HuntT1128 : public Hunt {
	public:
		HuntT1128();

		virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
		virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
	};
}