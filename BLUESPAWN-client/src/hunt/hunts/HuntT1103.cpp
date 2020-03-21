#include "hunt/hunts/HuntT1103.h"
#include "hunt/RegistryHunt.h"
#include "util/log/Log.h"
#include "util/configurations/Registry.h"

using namespace Registry;

namespace Hunts {
	HuntT1103::HuntT1103() : Hunt(L"T1103 - AppInit DLLs") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Processes;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
	}

	int HuntT1103::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO(L"Hunting for " << name << L"at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int detections = 0;

		for(auto& detection : CheckValues(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", {
			{ L"AppInit_Dlls", L"", false, CheckSzEmpty },
			{ L"LoadAppInit_Dlls", 0, false, CheckDwordEqual },
			{ L"RequireSignedAppInit_DLLs", 1, false, CheckDwordEqual },
		}, true, false)){
			reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(detection));
			detections++;
		}

		reaction.EndHunt();
		return detections;
	}

	std::vector<std::shared_ptr<Event>> HuntT1103::GetMonitoringEvents(){
		return GetRegistryEvents(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", true, false, false);
	}
}