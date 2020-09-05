#pragma once

#include "../Hunt.h"

namespace Hunts {

	/**
	 * HuntT1484 examines the local file system for presence of ntuser.man files which
	 * can be used to override GPO settings
	 */
	class HuntT1484 : public Hunt {
	public:
		HuntT1484();

		virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
		virtual std::vector<std::pair<std::unique_ptr<Event>, Scope>> GetMonitoringEvents() override;
	};
}