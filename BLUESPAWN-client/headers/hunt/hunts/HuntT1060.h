#pragma once
#include "../Hunt.h"
#include "hunt/reaction/Reaction.h"
#include "hunt/reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1060 examines associated Registry Run Keys
	 * 
	 * @scans Cursory checks the values of the associated Registry Run Keys
	 * @scans Moderate Scan not supported.
	 * @scans Careful Scan not supported.
	 * @scans Aggressive Scan not supported.
	 */
	class HuntT1060 : public Hunt {
	public:
		HuntT1060(HuntRegister& record);

		virtual int ScanCursory(const Scope& scope, Reaction reaction);
	};
}