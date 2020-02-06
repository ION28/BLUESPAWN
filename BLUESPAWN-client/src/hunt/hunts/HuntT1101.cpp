#include "hunt/hunts/HuntT1101.h"
#include "hunt/RegistryHunt.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"

using namespace Registry;

namespace Hunts {
	HuntT1101::HuntT1101(HuntRegister& record) : Hunt(record, L"T1101 - Security Support Provider") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	int HuntT1101::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for T1101 - Security Support Provider at level Cursory");
		reaction.BeginHunt(GET_INFO());

		std::map<RegistryKey, std::vector<RegistryValue>> keys;

		auto Lsa = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" };
		keys.emplace(Lsa, CheckValues(Lsa, {
			{L"Security Packages", RegistryType::REG_MULTI_SZ_T, okSecPackages, false, CheckMultiSzSubset },
		}));

		auto OSConfig = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig" };
		keys.emplace(OSConfig, CheckValues(OSConfig, {
			{L"Security Packages", RegistryType::REG_MULTI_SZ_T, okSecPackages, false, CheckMultiSzSubset },
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