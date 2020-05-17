#pragma once

#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts{

	/**
	 * HuntT1122 examines CLSID registry values to detect COM hijacking, used in
	 * persistence.
	 *
	 * @scans Cursory Scan not supported.
	 * @scans Normal Scan not supported.
	 * @scans Intensive Enumerates all CLSID values in the registry to detect COM hijacking.
	 */
	class HuntT1122 : public Hunt {
	public:
		HuntT1122();

		virtual int ScanIntensive(const Scope& scope, Reaction reaction) override;
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}