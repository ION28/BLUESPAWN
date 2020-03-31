#include "hunt/hunts/HuntT1101.h"
#include "hunt/RegistryHunt.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"

using namespace Registry;

namespace Hunts {
	HuntT1101::HuntT1101() : Hunt(L"T1101 - Security Support Provider") {
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	std::vector<std::shared_ptr<DETECTION>> HuntT1101::RunHunt(const Scope& scope){
		HUNT_INIT();

		auto safeSecPackages = okSecPackages;
		for(auto& detection : CheckValues(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", {
			{L"Security Packages", std::move(safeSecPackages), false, CheckMultiSzSubset },
		})){
			REGISTRY_DETECTION(detection);
		}

		safeSecPackages = okSecPackages;
		for(auto& detection : CheckValues(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig", {
			{L"Security Packages", std::move(safeSecPackages), false, CheckMultiSzSubset },
		})){
			REGISTRY_DETECTION(detection);
		}

		HUNT_END();
	}

	std::vector<std::shared_ptr<Event>> HuntT1101::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		events.push_back(std::make_shared<RegistryEvent>(RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" }));
		events.push_back(std::make_shared<RegistryEvent>(RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig" }));

		return events;
	}
}