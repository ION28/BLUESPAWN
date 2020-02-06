#pragma once
#include "../Hunt.h"
#include "hunt/reaction/Reaction.h"
#include "hunt/reaction/HuntTrigger.h"
#include "hunt/reaction/Log.h"

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
		HuntT1004(HuntRegister& record);

		virtual int ScanCursory(const Scope& scope, Reaction reaction) override;
	};
}