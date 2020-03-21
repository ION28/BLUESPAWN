#include "hunt/hunts/HuntT1131.h"
#include "hunt/RegistryHunt.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"

using namespace Registry;

namespace Hunts {
	HuntT1131::HuntT1131() : Hunt(L"T1131 - Authentication Package") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	int HuntT1131::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO(L"Hunting for " << name << L" at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int detections = 0;

		auto safeAuthPackages = okAuthPackages;
		auto safeNotifPackages = okNotifPackages;
		for(auto& detection : CheckValues(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", {
			{ L"Authentication Packages", std::move(safeAuthPackages), false, CheckMultiSzSubset },
			{ L"Notification Packages", std::move(safeNotifPackages), false, CheckMultiSzSubset },
		})){
			reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(detection));
			detections++;
		}

		reaction.EndHunt();
		return detections;
	}

	std::vector<std::shared_ptr<Event>> HuntT1131::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		events.push_back(std::make_shared<RegistryEvent>(RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" }));

		return events;
	}
}