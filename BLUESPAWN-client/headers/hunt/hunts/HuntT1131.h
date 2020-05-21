#pragma once
#include "../Hunt.h"

#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1131 examines the Authentication packages listed in the registry to 
	 * hunt for persistence.
	 * 
	 * @scans Cursory checks the values of the associated Authentication packages 
	 * keys that can be abused.
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
	class HuntT1131 : public Hunt {
	public:
		HuntT1131();

		virtual int ScanCursory(const Scope& scope, Reaction reaction);
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}