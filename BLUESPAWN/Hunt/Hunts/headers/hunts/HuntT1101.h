#pragma once
#include "Hunt.h"
#include "reactions/Reaction.h"
#include "reactions/Log.h"

#include "logging/Output.h"
#include "configuration/Registry.h"

namespace Hunts {

	/**
	 * HuntT1101 examines Security Support Providers (SSPs) on the system
	 * 
	 * @scans Cursory checks the names of the SSPs on the system.
	 * @scans Moderate Scan not supported.
	 * @scans Careful Scan not supported.
	 * @scans Aggressive Scan not supported.
	 */
	class HuntT1101 : public Hunt {
	private:
		vector<wstring> okSecPackages = { L"\"\"", L"wsauth", L"kerberos", L"msv1_0", L"schannel", L"wdigest", L"tspkg", L"pku2u" };

	public:
		HuntT1101(HuntRegister& record);

		int ScanCursory(Scope& scope, Reaction* reaction = new Reactions::Log());
	};
}