#include "hunts/HuntT1138.h"
#include "logging/Log.h"

namespace Hunts {
	HuntT1138::HuntT1138(HuntRegister& record) : Hunt(record) {
		dwSupportedScans = Aggressiveness::Cursory;
		dwStuffAffected = AffectedThing::Configurations;
		dwSourcesInvolved = DataSource::Registry;
		dwTacticsUsed = Tactic::Persistence | Tactic::PrivilegeEscalation;
	}

	int HuntT1138::ScanCursory(Scope& scope, Reaction* reaction){
		LOG_INFO("Hunting for T1138 - Application Shimming at level Cursory");

		int identified = 0;

		const int num_of_keys_to_inspect = 2;
		key keys[num_of_keys_to_inspect] = {
			{HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags", L"InstalledSDB", s2ws(""), REG_SZ},
			{HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags", L"Custom", s2ws(""), REG_SZ },
		};

		identified = ExamineRegistryKeySet(keys, num_of_keys_to_inspect);

		std::cout << std::endl;
		
		return identified;
	}

}