#include "hunts/HuntT1101.h"

#include "logging/Log.h"
#include "configuration/Registry.h"

using namespace Registry;

namespace Hunts {
	HuntT1101::HuntT1101(HuntRegister& record) : Hunt(record) {
		dwSupportedScans = Aggressiveness::Cursory;
		dwStuffAffected = AffectedThing::Configurations;
		dwSourcesInvolved = DataSource::Registry;
		dwTacticsUsed = Tactic::Persistence;
	}

	int HuntT1101::ScanCursory(Scope& scope, Reaction* reaction){
		LOG_INFO("Hunting for T1101 - Security Support Provider at level Cursory");

		int identified = 0;

		std::vector<RegistryKey> keys = {
		    {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Security Packages"},
		    {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig", L"Security Packages"},
		};

		for(auto key : keys){
			for(auto value : key.Get<REG_MULTI_SZ_T>()){

				bool good = true;
				if(find(okSecPackages.begin(), okSecPackages.end(), value) == okSecPackages.end()) {
					LOG_WARNING("Potentially malicious LSA security package discovered - " << value << "\n"
						<< "Registry key is " << key);
					good = false;
					identified++;
				}
				
				if(good){
					LOG_VERBOSE(1, "Registry key " << key.GetName() << " is okay");
				} else {
					reaction->RegistryKeyIdentified(key);
				}
			}
		}
		
		return identified;
	}

}