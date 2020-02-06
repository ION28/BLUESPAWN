#include "hunt/hunts/HuntT1050.h"
#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"
#include "util/log/HuntLogMessage.h"

namespace Hunts {

	HuntT1050::HuntT1050(HuntRegister& record) : Hunt(record, L"T1050 - New Service") {
		// TODO: update these categories
		dwSupportedScans = (DWORD) Aggressiveness::Intensive;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	int HuntT1050::ScanIntensive(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for T1050 - New Service at level Intensive");
		reaction.BeginHunt(GET_INFO());


		int identified = 0;
		identified += EventLogs::getLogs()->QueryEvents(L"System", 7045, std::set<std::wstring>({L"Event/EventData/Data[@Name='ServiceName']",
			L"Event/EventData/Data[@Name='ImagePath']", L"Event/EventData/Data[@Name='ServiceType']", L"Event/EventData/Data[@Name='StartType']" }), reaction);

		if (identified == -1) {
			LOG_ERROR("Hunting for T1050 - Event Query for 7045 failed.");
			identified = 0;
		}

		reaction.EndHunt();
		return identified;
	}

	void HuntT1050::SetupMonitoring(HuntRegister& record, const Scope& scope, Aggressiveness level, Reaction reaction) {
		Reactions::HuntTriggerReaction triggerReaction(record, dynamic_cast<Hunt*>(this), scope, level, reaction);
		DWORD status;
		eventSubscriptions.push_back(EventLogs::getLogs()->subscribe(L"System", 7045, triggerReaction, &status));

		if (status == ERROR_SUCCESS)
			LOG_INFO("Monitoring for T1050 - New Service at level Cursory");
		else
			LOG_WARNING("Monitoring for T1050 failed with error code " + std::to_string(status));
	}
}