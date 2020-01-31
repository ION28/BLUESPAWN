#include "hunt/hunts/HuntT1037.h"
#include "hunt/RegistryHunt.h"

#include "util/log/Log.h"

using namespace Registry;

namespace Hunts {
	HuntT1037::HuntT1037(HuntRegister& record) : Hunt(record, L"T1037 - Logon Scripts") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::LateralMovement;
	}

	int HuntT1037::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for T1037 - Logon Scripts at level Cursory");
		reaction.BeginHunt(GET_INFO());

		std::map<RegistryKey, std::vector<RegistryValue>> keys;

		auto HKCUEnvironment = RegistryKey{ HKEY_CURRENT_USER, L"Environment", };
		keys.emplace(HKCUEnvironment, CheckValues(HKCUEnvironment, {
			{ L"UserInitMprLogonScript", RegistryType::REG_SZ_T, L"", false, CheckSzEmpty } 
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