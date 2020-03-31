#include "hunt/hunts/HuntT1138.h"
#include "hunt/RegistryHunt.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"

#include "common/Utils.h"

using namespace Registry;

namespace Hunts {
	HuntT1138::HuntT1138() : Hunt(L"T1138 - Application Shimming") {
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
	}

	std::vector<std::shared_ptr<DETECTION>> HuntT1138::RunHunt(const Scope& scope){
		HUNT_INIT();

		auto& values = CheckKeyValues(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB", true, false);
		ADD_ALL_VECTOR(values, CheckKeyValues(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom", true, false));

		for(const auto& detection : values){
			REGISTRY_DETECTION(detection);
		}

		HUNT_END();
	}

	std::vector<std::shared_ptr<Event>> HuntT1138::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		ADD_ALL_VECTOR(events, GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB"));
		ADD_ALL_VECTOR(events, GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom"));

		return events;
	}
}