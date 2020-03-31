#pragma once
#include "../Hunt.h"

#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1131 examines the Authentication packages listed in the registry to 
	 * hunt for persistence.
	 */
	class HuntT1131 : public Hunt {
	private:
		std::vector<std::wstring> okAuthPackages = { L"msv1_0", L"SshdPinAuthLsa" };
		std::vector<std::wstring> okNotifPackages = { L"scecli" };
	public:
		HuntT1131();

		virtual std::vector<std::shared_ptr<DETECTION>> RunHunt(const Scope& scope);
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}