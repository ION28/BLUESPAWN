#include "hunts/HuntT1060.h"

namespace Hunts {
	HuntT1060::HuntT1060(HuntRegister& record) : Hunt(record) {
		dwSupportedScans = Aggressiveness::Cursory;
		dwStuffAffected = AffectedThing::Configurations;
		dwSourcesInvolved = DataSource::Registry;
		dwTacticsUsed = Tactic::Persistence;
	}

	int HuntT1060::ScanCursory(Scope& scope, Reaction* reaction){
		PrintInfoHeader("Hunting for T1060 - Registry Run Keys / Startup Folder at level Cursory");

		int identified = 0;

		const int num_of_keys_to_inspect = 15;
		key keys[num_of_keys_to_inspect] = {
			{HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"*", s2ws("*"), REG_SZ},
			{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"*", s2ws("*"), REG_SZ},
			{HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"*", s2ws("*"), REG_SZ},
			{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"*", s2ws("*"), REG_SZ},
			{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", L"*", s2ws("*"), REG_SZ},
			{HKEY_CURRENT_USER,L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", L"*", s2ws("*"), REG_SZ},
			{HKEY_LOCAL_MACHINE,L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", L"*", s2ws("*"), REG_SZ},
			{HKEY_CURRENT_USER,L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"*", s2ws("*"), REG_SZ},
			{HKEY_LOCAL_MACHINE,L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"*", s2ws("*"), REG_SZ},
			{HKEY_LOCAL_MACHINE,L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", L"*", s2ws("*"), REG_SZ},
			{HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", L"*", s2ws("*"), REG_SZ},
			{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", L"*", s2ws("*"), REG_SZ},
			{HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", L"Startup", s2ws("%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"), REG_SZ},
			{HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", L"Common Startup", s2ws("%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"), REG_SZ},
			{HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", L"Common Startup", s2ws("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"), REG_SZ},
		};

		identified = ExamineRegistryKeySet(keys, num_of_keys_to_inspect);

		std::cout << std::endl;
		
		return identified;
	}

}