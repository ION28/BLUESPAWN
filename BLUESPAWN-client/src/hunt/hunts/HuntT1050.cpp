#include "hunt/hunts/HuntT1050.h"
#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"
#include "util/log/HuntLogMessage.h"

namespace Hunts {

	HuntT1050::HuntT1050(HuntRegister& record) : Hunt(record, L"T1050 - New Service") {
		// TODO: update these categories
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	int HuntT1050::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for T1050 - New Service at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int identified = 0;
		identified += QueryEvents(L"System", 7045, std::set<std::wstring>({L"Event/EventData/Data[@Name='ServiceName']", 
			L"Event/EventData/Data[@Name='ImagePath']", L"Event/EventData/Data[@Name='ServiceType']", L"Event/EventData/Data[@Name='StartType']" }), reaction);

		if (identified == -1) {
			LOG_ERROR("Hunting for T1050 - Event Query for 7045 failed.");
			identified = 0;
		}

		reaction.EndHunt();
		return identified;
	}

}