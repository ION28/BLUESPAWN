#pragma once
#include <Windows.h>

#include <vector>

#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1101 examines Security Support Providers (SSPs) on the system
	 * 
	 * @scans Cursory scans the SSPs installed on the system and their DLLs.
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
	class HuntT1101 : public Hunt {
	public:
		HuntT1101();

		virtual int ScanCursory(const Scope& scope, Reaction reaction);
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}