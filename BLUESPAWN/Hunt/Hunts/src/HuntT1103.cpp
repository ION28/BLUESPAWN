#include "hunts/HuntT1103.h"
#include "logging/Log.h"

namespace Hunts {
	HuntT1103::HuntT1103(HuntRegister& record) : Hunt(record) {
		dwSupportedScans = Aggressiveness::Cursory;
		dwStuffAffected = AffectedThing::Configurations;
		dwSourcesInvolved = DataSource::Registry;
		dwTacticsUsed = Tactic::Persistence | Tactic::PrivilegeEscalation;
	}

	int HuntT1103::ScanCursory(Scope& scope, Reaction* reaction){
		LOG_INFO("Hunting for T1103 - AppInit DLLs at level Cursory");

		int identified = 0;

		const int num_of_keys_to_inspect = 4;
		key keys[num_of_keys_to_inspect] = {
			{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs", s2ws(""), REG_SZ},
			{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"LoadAppInit_DLLs", s2ws("0"), REG_DWORD},
			{HKEY_LOCAL_MACHINE,L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs", s2ws(""), REG_SZ},
			{HKEY_LOCAL_MACHINE,L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"LoadAppInit_DLLs", s2ws("0"), REG_DWORD},
		};

		identified = ExamineRegistryKeySet(keys, num_of_keys_to_inspect);

		std::cout << std::endl;
		
		return identified;
	}

}