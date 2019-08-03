#include "hunts/HuntT1004.h"
#include "logging/Log.h"

namespace Hunts {
	HuntT1004::HuntT1004(HuntRegister& record) : Hunt(record) {
		dwSupportedScans = Aggressiveness::Cursory;
		dwStuffAffected = AffectedThing::Configurations;
		dwSourcesInvolved = DataSource::Registry;
		dwTacticsUsed = Tactic::Persistence;
	}

	int HuntT1004::ScanCursory(Scope& scope, Reaction* reaction){
		LOG_INFO("Hunting for T1004 - Winlogon Helper DLL at level Cursory");

		int identified = 0;

		const int num_of_keys_to_inspect = 7;
		key keys[num_of_keys_to_inspect] = {
			{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", L"explorer.exe"},
			{HKEY_LOCAL_MACHINE,L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", L"explorer.exe"},
			{HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", L""},
			{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit", L"C:\\Windows\\system32\\userinit.exe"},
			{HKEY_LOCAL_MACHINE,L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit", L""},
			{HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit", L""},
			{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", L"*", L"*"},
		};

		identified = ExamineRegistryKeySet(keys, num_of_keys_to_inspect);

		std::cout << std::endl;
		
		return identified;
	}

}