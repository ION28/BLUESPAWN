#pragma once
#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1004 examines Winlogon related registry keys that can be used for
	 * persistence.
	 * 
	 * @scans Cursory checks the values of the associated Winlogon keys that can be abused.
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
	class HuntT1004 : public Hunt {
	public:
		HuntT1004();

		virtual int ScanCursory(const Scope& scope, Reaction reaction) override;
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}