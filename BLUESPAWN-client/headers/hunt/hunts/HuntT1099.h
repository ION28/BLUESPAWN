#pragma once
#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1099 examines Sysmon logs looking for timestomp events
	 *
	 * @scans Cursory Scan not supported.
	 * @scans Normal checks Sysmon logs for event id 2 (file MAC time change), 
	 *		scans Timestomp file with YARA.
	 * @scans Intensive checks Sysmon logs for event id 2 (file MAC time change).
	 * @monitor Triggers a hunt whenever Sysmon log event ID 2 is generated
	 */
	class HuntT1099 : public Hunt {
	public:
		HuntT1099();

		virtual int ScanNormal(const Scope& scope, Reaction reaction) override;
		virtual int ScanIntensive(const Scope& scope, Reaction reaction) override;
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}
