#include "hunts/HuntT1101.h"
#include "logging/Log.h"

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

		key keys[2] = {
		{HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Security Packages", s2ws("*"), REG_MULTI_SZ},
		{HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig", L"Security Packages", s2ws("*"), REG_MULTI_SZ},
		};

		for (int i = 0; i < 2; i++) {
			HKEY hKey;
			LONG lRes = RegOpenKeyEx(keys[i].hive, keys[i].path, 0, KEY_READ, &hKey);
			bool bExistsAndSuccess(lRes == ERROR_SUCCESS);

			if (bExistsAndSuccess) {
				wstring key_name = keys[i].key;
				wstring result;
				vector<wstring> target;
				GetRegistryKey(hKey, keys[i].type, result, key_name, target);
				RegCloseKey(hKey);

				bool foundBad = false;
				for (auto& val : target) {
					if (find(okSecPackages.begin(), okSecPackages.end(), val) == okSecPackages.end()) {
						PrintBadStatus("Key is non-default: " + hive2s(keys[i].hive) + (string)"\\" + ws2s(keys[i].path) + (string)"\\" + ws2s(keys[i].key));
						PrintInfoStatus("Found potentially bad package: " + ws2s(val));
						foundBad = true;
						identified++;
					}
				}
				if (!foundBad) {
					PrintGoodStatus("Key is okay: " + hive2s(keys[i].hive) + (string)"\\" + ws2s(keys[i].path) + (string)"\\" + ws2s(keys[i].key));
				}
			}
			else {
				PrintGoodStatus("Key is okay: " + hive2s(keys[i].hive) + (string)"\\" + ws2s(keys[i].path) + (string)"\\" + ws2s(keys[i].key));
			}
		}

		std::cout << std::endl;
		
		return identified;
	}

}