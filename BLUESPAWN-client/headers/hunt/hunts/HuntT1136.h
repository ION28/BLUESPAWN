#pragma once
#include "../Hunt.h"
#include "hunt/reaction/Reaction.h"
#include "hunt/reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1136 examines Windows events for new accounts created
	 *
	 * @scans Cursory checks Security logs for event id 4720 for new accounts
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 * @monitor Triggers a hunt whenever Security log event ID 4720 is generated
	 */
	class HuntT1136 : public Hunt {
	public:
		HuntT1136();

		virtual int ScanCursory(const Scope& scope, Reaction reaction) override;
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}
#pragma once
