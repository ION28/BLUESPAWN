#include "hunts/HuntT1131.h"

namespace Hunts {
	HuntT1131::HuntT1131(HuntRegister& record) : Hunt(record) {
		dwSupportedScans = Aggressiveness::Cursory;
		dwStuffAffected = AffectedThing::Configurations;
		dwSourcesInvolved = DataSource::Registry;
		dwTacticsUsed = Tactic::Persistence;
	}

	int HuntT1131::ScanCursory(Scope& scope, Reaction* reaction){
		PrintInfoHeader("Hunting for T1131 - Authentication Package at level Cursory");

		int identified = 0;

		key keys[2] = {
		{HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Authentication Packages", s2ws("*"), REG_MULTI_SZ},
		{HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Notification Packages", s2ws("*"), REG_MULTI_SZ},
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
					if (i == 0) {
						if (find(okAuthPackages.begin(), okAuthPackages.end(), val) == okAuthPackages.end()) {
							PrintBadStatus("Key is non-default: " + hive2s(keys[i].hive) + (string)"\\" + ws2s(keys[i].path) + (string)"\\" + ws2s(keys[i].key));
							PrintInfoStatus("Found potentially bad package: " + ws2s(val));
							foundBad = true;
							identified++;
						}
					}
					else if (i == 1) {
						if (find(okNotifPackages.begin(), okNotifPackages.end(), val) == okNotifPackages.end()) {
							PrintBadStatus("Key is non-default: " + hive2s(keys[i].hive) + (string)"\\" + ws2s(keys[i].path) + (string)"\\" + ws2s(keys[i].key));
							PrintInfoStatus("Found potentially bad package: " + ws2s(val));
							foundBad = true;
							identified++;
						}
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