#pragma once
#include <Windows.h>

#include <vector>

#include "../Hunt.h"

namespace Hunts {

	/**
	 * HuntT1035 examines the system for malicious services
	 * 
	 * @scans Cursory scans the services that are installed and their binaries
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
	class HuntT1035 : public Hunt {
	public:
		HuntT1035();

		virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
		virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
	};
}