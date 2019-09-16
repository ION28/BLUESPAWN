#pragma once
#include "Hunt.h"
#include "reactions/Reaction.h"
#include "reactions/Log.h"

namespace Hunts {

	/**
	 * HuntT1138 examines the system for the presence of Application Shimming that can
	 * be used for persistence and privilege escalation.
	 * 
	 * @scans Cursory checks the values of the associated Application Shimming registry
	 * keys that can be abused.
	 * @scans Moderate Scan not supported.
	 * @scans Careful Scan not supported.
	 * @scans Aggressive Scan not supported.
	 */
	class HuntT1138 : public Hunt {
	public:
		HuntT1138(HuntRegister& record);

		virtual int ScanCursory(const Scope& scope, Reaction reaction);
	};
}