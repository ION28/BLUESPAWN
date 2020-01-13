#pragma once
#include "../Hunt.h"

#include "hunt/reaction/Reaction.h"
#include "hunt/reaction/Log.h"
#include "util/configurations/Registry.h"

namespace Hunts {

	/**
	 * HuntT1037 examines the registry for logon scripts
	 * 
	 * @scans Cursory checks the value of the UserInitMprLogonScript key for scripts
	 * @scans Moderate Scan not supported.
	 * @scans Careful Scan not supported.
	 * @scans Aggressive Scan not supported.
	 */
	class HuntT1037 : public Hunt {
	public:
		HuntT1037(HuntRegister& record);

		virtual int ScanCursory(const Scope& scope, Reaction reaction);
	};
}