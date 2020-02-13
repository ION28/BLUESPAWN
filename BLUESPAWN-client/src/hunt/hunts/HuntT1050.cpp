#include "hunt/hunts/HuntT1050.h"
#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"
#include "util/log/HuntLogMessage.h"

namespace Hunts {

	HuntT1050::HuntT1050() : Hunt(L"T1050 - New Service") {
		// TODO: update these categories
		dwSupportedScans = (DWORD) Aggressiveness::Intensive;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	int HuntT1050::ScanIntensive(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for T1050 - New Service at level Intensive");
		reaction.BeginHunt(GET_INFO());

		// std::vector<std::wstring>({L"Event/EventData/Data[@Name='ServiceName']",
		//L"Event/EventData/Data[@Name='ImagePath']", L"Event/EventData/Data[@Name='ServiceType']", L"Event/EventData/Data[@Name='StartType']"
		//})
		auto results = EventLogs::QueryEvents(L"System", 7045);
		for (auto result : results)
			reaction.EventIdentified(EventLogs::EventLogItemToDetection(result));

		reaction.EndHunt();
		return results.size();
	}

	std::vector<std::shared_ptr<Event>> HuntT1050::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;
		events.push_back(std::make_shared<EventLogEvent>(L"System", 7045));
		return events;
	}
}