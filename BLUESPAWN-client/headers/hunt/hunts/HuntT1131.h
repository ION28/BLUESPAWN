#pragma once
#include "../Hunt.h"

#include <unordered_set>

namespace Hunts {

	/**
	 * HuntT1131 examines the Authentication packages listed in the registry to 
	 * hunt for persistence.
	 */
	class HuntT1131 : public Hunt {
	private:
		std::unordered_set<std::wstring> okAuthPackages = { L"msv1_0", L"SshdPinAuthLsa" };
		std::unordered_set<std::wstring> okNotifPackages = { L"scecli" };
	public:
		HuntT1131();

		virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope);
		virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
	};
}