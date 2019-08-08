#pragma once
#include <Windows.h>

#include "Hunt.h"
#include "reactions/Reaction.h"
#include "reactions/Log.h"

namespace Hunts {

	/**
	 * HuntT1004 examines AppInit DLLs related registry keys that can be used for
	 * persistence and privilege escalation.
	 * 
	 * @scans Cursory checks the values of the associated AppInit DLLs keys that can be abused.
	 * @scans Moderate Scan not supported.
	 * @scans Careful Scan not supported.
	 * @scans Aggressive Scan not supported.
	 */
	class HuntT1103 : public Hunt {
	public:
		HuntT1103(HuntRegister& record);

		int ScanCursory(Scope& scope, Reaction* reaction = new Reactions::LogReaction());
	};
}