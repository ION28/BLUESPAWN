#include "hunt/hunts/HuntT1004.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"
#include "util/log/HuntLogMessage.h"
#include "util/eventlogs/EventLogs.h"

#include "common/Utils.h"

#include <algorithm>

using namespace Registry;

namespace Hunts {

	HuntT1004::HuntT1004() : Hunt(L"T1004 - Winlogon Helper DLL") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	int HuntT1004::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for " << name << " at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int detections = 0;

		std::vector<RegistryValue> winlogons{ CheckValues(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", {
			{ L"Shell", L"explorer\\.exe,?", false, CheckSzRegexMatch },
			{ L"UserInit", L"(C:\\\\(Windows|WINDOWS|windows)\\\\(System32|SYSTEM32|system32)\\\\)?(U|u)(SERINIT|serinit)\\.(exe|EXE),?", false, CheckSzRegexMatch }
		}, true, true) };
		for(auto& detection : winlogons){
			reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(detection));
			detections++;
		}

		std::vector<RegistryValue> notifies{ CheckKeyValues(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", true, true) };
		for(auto& notify : CheckSubkeys(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", true, true)){
			if(notify.ValueExists(L"DllName")){
				notifies.emplace_back(RegistryValue{ notify, L"DllName", *notify.GetValue<std::wstring>(L"DllName") });
			}
		}
		for(auto& detection : notifies){
			reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(detection));
			detections++;
		}

		reaction.EndHunt();
		return detections;
	}

	std::vector<std::shared_ptr<Event>> HuntT1004::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"));
		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Notify", true, true, true));

		return events;
	}
}