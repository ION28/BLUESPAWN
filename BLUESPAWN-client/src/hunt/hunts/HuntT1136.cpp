#include "hunt/hunts/HuntT1136.h"
#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"
#include "util/log/HuntLogMessage.h"

namespace Hunts {

	HuntT1136::HuntT1136() : Hunt(L"T1136 - Account Created") {
		dwSupportedScans = (DWORD)Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD)Category::Configurations;
		dwSourcesInvolved = (DWORD)DataSource::EventLogs;
		dwTacticsUsed = (DWORD)Tactic::Persistence;
	}

	int HuntT1136::ScanCursory(const Scope& scope, Reaction reaction) {
		LOG_INFO("Hunting for T1136 - Account Created");
		reaction.BeginHunt(GET_INFO());


		int identified = 0;
		identified += EventLogs::getLogs()->QueryEvents(L"Security", 4720, std::set<std::wstring>({ L"Event/EventData/Data[@Name='TargetUserName']",
			L"Event/EventData/Data[@Name='SubjectUserName']" }), reaction);

		if (identified == -1) {
			LOG_ERROR("Hunting for T1136 - Event Query for 4720 failed.");
			identified = 0;
		}

		reaction.EndHunt();
		return identified;
	}

	std::vector<std::shared_ptr<Event>> HuntT1136::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;
		events.push_back(std::make_shared<EventLogEvent>(L"Security", 4720));
		return events;
	}
}