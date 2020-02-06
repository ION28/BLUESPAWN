#pragma once
#include "../Hunt.h"

#include "hunt/reaction/Reaction.h"
#include "hunt/reaction/Log.h"

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
	private:
		std::vector<std::wstring> okAuthPackages = { L"msv1_0", L"SshdPinAuthLsa" };
		std::vector<std::wstring> okNotifPackages = { L"scecli" };
	public:
		HuntT1131();

		virtual int ScanCursory(const Scope& scope, Reaction reaction);
	};
}