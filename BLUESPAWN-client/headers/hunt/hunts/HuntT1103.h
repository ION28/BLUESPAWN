#pragma once
#include <Windows.h>

#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1103 examines AppInit DLLs related registry keys that can be used for
	 * persistence and privilege escalation.
	 * 
	 * @scans Cursory checks the values of the associated AppInit DLLs keys that can be abused.
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
	class HuntT1103 : public Hunt {
	public:
		HuntT1103();

		virtual int ScanCursory(const Scope& scope, Reaction reaction);
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}