#pragma once
#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1013 examines the registry for bad port monitors
	 * 
	 * @scans Cursory checks for bad DLLs configured as port monitors
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
	class HuntT1013 : public Hunt {
	public:
		HuntT1013();

		virtual int ScanCursory(const Scope& scope, Reaction reaction) override;
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}