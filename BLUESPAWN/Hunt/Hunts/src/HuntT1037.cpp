#include "hunts/HuntT1037.h"

namespace Hunts {
	HuntT1037::HuntT1037(HuntRegister& record) : Hunt(record) {
		dwSupportedScans = Aggressiveness::Cursory;
		dwStuffAffected = AffectedThing::Configurations;
		dwSourcesInvolved = DataSource::Registry;
		dwTacticsUsed = Tactic::Persistence | Tactic::LateralMovement;
	}

	int HuntT1037::ScanCursory(Scope& scope, Reaction* reaction){
		PrintInfoHeader("Hunting for T1037 - Logon Scripts at level Cursory");

		int identified = 0;

		const int num_of_keys_to_inspect = 1;
		key keys[num_of_keys_to_inspect] = {
			{HKEY_CURRENT_USER,L"Environment",L"UserInitMprLogonScript", s2ws(""), REG_SZ},
		};

		identified = ExamineRegistryKeySet(keys, num_of_keys_to_inspect);

		std::cout << std::endl;
		
		return identified;
	}

}