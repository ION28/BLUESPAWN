#pragma once
#include "Hunt.h"
#include "reactions/Reaction.h"
#include "reactions/Log.h"

#include "logging/Output.h"
#include "configuration/Registry.h"

namespace Hunts {

	/**
	 * HuntT1131 examines the Authentication packages listed in the registry to 
	 * hunt for persistence.
	 * 
	 * @scans Cursory checks the values of the associated Authentication packages 
	 * keys that can be abused.
	 * @scans Moderate Scan not supported.
	 * @scans Careful Scan not supported.
	 * @scans Aggressive Scan not supported.
	 */
	class HuntT1131 : public Hunt {
	private:
		vector<wstring> okAuthPackages = { L"msv1_0", L"SshdPinAuthLsa" };
		vector<wstring> okNotifPackages = { L"scecli" };
	public:
		HuntT1131(HuntRegister& record);

		int ScanCursory(Scope& scope, Reaction* reaction = new Reactions::Log());
	};
}