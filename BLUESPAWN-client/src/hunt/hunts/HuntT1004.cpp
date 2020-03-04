#include "hunt/hunts/HuntT1004.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"
#include "util/log/HuntLogMessage.h"
#include "util/eventlogs/EventLogs.h"
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

		std::vector<RegistryValue> winlogons{ CheckValues(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", {
			{ L"Shell", L"explorer\\.exe,?", true, CheckSzRegexMatch },
			{ L"UserInit", L"(C:\\\\(Windows|WINDOWS|windows)\\\\(System32|SYSTEM32|system32)\\\\)?(U|u)(SERINIT|serinit)\\.(exe|EXE),?", false, CheckSzRegexMatch }
		}, true, true) };
		std::for_each(winlogons.begin(), winlogons.end(), [&reaction](const RegistryValue& v){ reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(v)); });

		std::vector<RegistryValue> notifies{ CheckKeyValues(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", true, true) };
		for(auto& notify : CheckSubkeys(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", true, true)){
			notifies.emplace_back(RegistryValue{ notify, L"DllName", *notify.GetValue<std::wstring>(L"DllName") });
		}
		std::for_each(notifies.begin(), notifies.end(), [&reaction](const RegistryValue& v){ reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(v)); });

		reaction.EndHunt();
		return notifies.size() + winlogons.size();
	}

	std::vector<std::shared_ptr<Event>> HuntT1004::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		std::vector<std::shared_ptr<Event>> winlogon{ Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") };
		std::vector<std::shared_ptr<Event>> notify{ Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Notify", true, true, true) };

		std::merge(winlogon.begin(), winlogon.end(), notify.begin(), notify.end(), std::back_inserter(events));

		return events;
	}
}