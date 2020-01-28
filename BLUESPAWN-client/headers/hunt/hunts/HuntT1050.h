#pragma once
#include "../Hunt.h"
#include "hunt/reaction/Reaction.h"
#include "hunt/reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1050 examines Windows events for new services created
	 *
	 * @scans Cursory checks System logs for event id 7045 for new events
	 * @scans Moderate Scan not supported.
	 * @scans Careful Scan not supported.
	 * @scans Aggressive Scan not supported.
	 */
	class HuntT1050 : public Hunt {
	public:
		HuntT1050(HuntRegister& record);

		virtual int ScanCursory(const Scope& scope, Reaction reaction) override;
	};
}
