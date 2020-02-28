#pragma once
#include <Windows.h>

#include <vector>

#include "../Hunt.h"
#include "hunt/reaction/Reaction.h"
#include "hunt/reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1101 examines Security Support Providers (SSPs) on the system
	 * 
	 * @scans Cursory checks the names of the SSPs on the system.
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
	class HuntT1101 : public Hunt {
	private:
		std::vector<std::wstring> okSecPackages = { L"\"\"", L"wsauth", L"kerberos", L"msv1_0", L"schannel", L"wdigest", L"tspkg", L"pku2u" };

	public:
		HuntT1101();

		virtual int ScanCursory(const Scope& scope, Reaction reaction);
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}