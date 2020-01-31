#include "hunt/hunts/HuntT1182.h"
#include "hunt/RegistryHunt.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"

using namespace Registry;

namespace Hunts {
	HuntT1182::HuntT1182(HuntRegister& record) : Hunt(record, L"T1182 - AppCert DLLs") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
	}

	int HuntT1182::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for T1182 - AppCert DLLs at level Cursory");
		reaction.BeginHunt(GET_INFO());

		std::map<RegistryKey, std::vector<RegistryValue>> keys;

		auto SessMan = RegistryKey{ HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager" };

		auto LSA = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" };
		keys.emplace(LSA, CheckValues(LSA, {
			{ L"AppCertDLLs", RegistryType::REG_MULTI_SZ_T, std::vector<std::wstring>{}, false, CheckMultiSzEmpty },
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