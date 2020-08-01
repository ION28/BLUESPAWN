#pragma once
#include "../Hunt.h"

namespace Hunts {

	/**
	 * HuntT1068 examines the registry and file system for evidence of CVE-2020-1048.
	 */
	class HuntT1068 : public Hunt {
	public:
		HuntT1068();

		virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
		virtual std::vector<std::pair<std::unique_ptr<Event>, Scope>> GetMonitoringEvents() override;
	};
}