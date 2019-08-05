#include "hunts/HuntT1182.h"
#include "logging/Log.h"

namespace Hunts {
	HuntT1182::HuntT1182(HuntRegister& record) : Hunt(record) {
		dwSupportedScans = Aggressiveness::Cursory;
		dwStuffAffected = AffectedThing::Configurations;
		dwSourcesInvolved = DataSource::Registry;
		dwTacticsUsed = Tactic::Persistence | Tactic::PrivilegeEscalation;
	}

	int HuntT1182::ScanCursory(Scope& scope, Reaction* reaction){
		LOG_INFO("Hunting for T1182 - AppCert DLLs at level Cursory");

		int identified = 0;

		/*

		//https://b3n7s.github.io/2018/10/27/AppCert-Dlls.html

		const int num_of_keys_to_inspect = 1;
		key keys[num_of_keys_to_inspect] = {
			{HKEY_LOCAL_MACHINE,L"System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls", L"*", s2ws("*"), REG_SZ},
		};

		identified = ExamineRegistryKeySet(keys, num_of_keys_to_inspect);

		std::cout << std::endl;

		*/
		
		return identified;
	}

}