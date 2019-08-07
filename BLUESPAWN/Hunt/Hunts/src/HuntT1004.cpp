#include "hunts/HuntT1004.h"
#include "hunts/RegistryHunt.hpp"

#include "configuration/Registry.h"
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

		int identified = 0;

		identified += CheckKey<REG_SZ_T>({ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell" }, L"explorer.exe", reaction);
		identified += CheckKey<REG_SZ_T>({ HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell" }, L"explorer.exe", reaction);
		identified += CheckKey<REG_SZ_T>({ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell"}, L"", reaction);
		identified += CheckKey<REG_SZ_T>({ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit"}, L"C:\\Windows\\System32\\userinit.exe", reaction);
		identified += CheckKey<REG_SZ_T>({ HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit"}, L"", reaction);
		identified += CheckKey<REG_SZ_T>({ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit"}, L"", reaction);

		for(auto key : RegistryKey(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify").Subkeys()){
			reaction->RegistryKeyIdentified(key);
		}

		return identified;
	}

}