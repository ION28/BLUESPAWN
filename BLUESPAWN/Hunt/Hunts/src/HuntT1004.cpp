#include "hunts/HuntT1004.h"
#include "logging/Log.h"

using namespace Registry;

namespace Hunts {
	HuntT1004::HuntT1004(HuntRegister& record) : Hunt(record) {
		dwSupportedScans = Aggressiveness::Cursory;
		dwStuffAffected = AffectedThing::Configurations;
		dwSourcesInvolved = DataSource::Registry;
		dwTacticsUsed = Tactic::Persistence;
	}

	int HuntT1004::ScanCursory(Scope& scope, Reaction* reaction){
		LOG_INFO("Hunting for T1004 - Winlogon Helper DLL at level Cursory");

		typedef struct _KeyValuePairing {
			RegistryKey key;
			std::wstring value;
		} KeyValuePairing;

		std::vector<KeyValuePairing> vKeyValuePairs{
			{{HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell"}, L"explorer.exe"},
			{{HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell"}, L"explorer.exe"},
			{{HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell"}, L""},
			{{HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit"}, L"C:\\Windows\\system32\\userinit.exe"},
			{{HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit"}, L""},
			{{HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit"}, L""},
			{{HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", L"*"}, L"*"},
		};

		int identified = 0;
		for(auto pair : vKeyValuePairs){
			if(!(pair.key == pair.value)){
				identified++;

				reaction->RegistryKeyIdentified(pair.key);
			}
		}
		
		return identified;
	}

}