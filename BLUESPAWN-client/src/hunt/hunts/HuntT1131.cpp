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
		LOG_INFO("Hunting for T1131 - Authentication Package at level Cursory");
		reaction.BeginHunt(GET_INFO());

		std::map<RegistryKey, std::vector<RegistryValue>> keys;

		auto LSA = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" };
		keys.emplace(LSA, CheckValues(LSA, {
			{ L"Authentication Packages", RegistryType::REG_MULTI_SZ_T, okAuthPackages, false, CheckMultiSzSubset },
			{ L"Notification Packages", RegistryType::REG_MULTI_SZ_T, okNotifPackages, false, CheckMultiSzSubset },
		}));

		int detections = 0;
		for(const auto& key : keys){
			for(const auto& value : key.second){
				reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(key.first.GetName(), value));
				detections++;
			}
		}

		reaction.EndHunt();
		return detections;
	}

}