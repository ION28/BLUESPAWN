#pragma once
#include <Windows.h>

#include <vector>

#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1101 examines Security Support Providers (SSPs) on the system
	 */
	class HuntT1101 : public Hunt {
	private:
		std::vector<std::wstring> okSecPackages = { L"\"\"", L"wsauth", L"kerberos", L"msv1_0", L"schannel", L"wdigest", L"tspkg", L"pku2u" };

	public:
		HuntT1101();

		virtual std::vector<std::shared_ptr<DETECTION>> RunHunt(const Scope& scope);
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}