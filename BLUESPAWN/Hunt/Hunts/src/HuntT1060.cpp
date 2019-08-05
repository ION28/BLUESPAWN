#include "hunts/HuntT1060.h"
#include "logging/Log.h"

using namespace Registry;

namespace Hunts {
	HuntT1060::HuntT1060(HuntRegister& record) : Hunt(record) {
		dwSupportedScans = Aggressiveness::Cursory;
		dwStuffAffected = AffectedThing::Configurations;
		dwSourcesInvolved = DataSource::Registry;
		dwTacticsUsed = Tactic::Persistence;
	}

	int HuntT1060::ScanCursory(Scope& scope, Reaction* reaction){
		LOG_INFO("Hunting for T1060 - Registry Run Keys / Startup Folder at level Cursory");

		int identified = 0;

		/*

		std::vector<KeyValuePairing> vKeyValuePairs{
			{{HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"*", s2ws("*"), REG_SZ},
			{{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"*", s2ws("*"), REG_SZ},
			{{HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"*", s2ws("*"), REG_SZ},
			{{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"*", s2ws("*"), REG_SZ},
			{{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", L"*", s2ws("*"), REG_SZ},
			{{HKEY_CURRENT_USER,L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", L"*", s2ws("*"), REG_SZ},
			{{HKEY_LOCAL_MACHINE,L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", L"*", s2ws("*"), REG_SZ},
			{{HKEY_CURRENT_USER,L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"*", s2ws("*"), REG_SZ},
			{{HKEY_LOCAL_MACHINE,L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"*", s2ws("*"), REG_SZ},
			{{HKEY_LOCAL_MACHINE,L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", L"*", s2ws("*"), REG_SZ},
			{{HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", L"*", s2ws("*"), REG_SZ},
			{{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", L"*", s2ws("*"), REG_SZ},
			{{HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", L"Startup"}, L"%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"},
			{{HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", L"Common Startup"}, L"%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"},
			{{HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", L"Common Startup"}, L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"},
		};

		for (auto pair : vKeyValuePairs) {
			if (!(pair.key == pair.value)) {
				identified++;

				reaction->RegistryKeyIdentified(pair.key);
			}
		}

		*/

		return identified;
	}

}