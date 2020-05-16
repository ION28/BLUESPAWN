#include "hunt/hunts/HuntT1068.h"

#include "util/log/Log.h"
#include "util/filesystem/FileSystem.h"

namespace Hunts {

	HuntT1068::HuntT1068() : Hunt(L"T1484 - Exploitation for Privilege Escalation") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
		dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
		dwTacticsUsed = (DWORD) Tactic::PrivilegeEscalation;
	}

	int HuntT1068::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for " << name << " at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int detections = 0;



		reaction.EndHunt();
		return detections;
	}

	std::vector<std::shared_ptr<Event>> HuntT1068::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;



		return events;
	}
}