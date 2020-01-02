#pragma once
#include "../Hunt.h"
#include "util/reaction/Reaction.h"
#include "util/reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1182 examines AppCert DLLs related registry keys that can be used for
	 * persistence and privilege escalation.
	 * 
	 * @scans Cursory checks the values of the associated AppCert DLLs keys that
	 * can be abused.
	 * @scans Moderate Scan not supported.
	 * @scans Careful Scan not supported.
	 * @scans Aggressive Scan not supported.
	 */
	class HuntT1182 : public Hunt {
	public:
		HuntT1182(HuntRegister& record);

		virtual int ScanCursory(const Scope& scope, Reaction reaction);
	};
}