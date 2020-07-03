#pragma once
#include <Windows.h>

#include <vector>

#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1035 examines the system for malicious services
	 * 
	 * @scans Cursory scans the services that are installed and their binaries
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
	class HuntT1035 : public Hunt {
	private:

		int EvaluateService(Registry::RegistryKey key, Reaction& reaction);

	public:
		HuntT1035();

		virtual int ScanNormal(const Scope& scope, Reaction reaction);
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}