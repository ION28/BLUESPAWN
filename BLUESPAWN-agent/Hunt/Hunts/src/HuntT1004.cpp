#include "hunts/HuntT1004.h"
#include "hunts/RegistryHunt.hpp"

#include "configuration/Registry.h"
#include "logging/Log.h"
#include "logging/HuntLogMessage.h"

using namespace Registry;

namespace Hunts {

	HuntT1004::HuntT1004(HuntRegister& record) : Hunt(record, L"T1004 - Winlogon Helper DLL") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	int HuntT1004::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for T1004 - Winlogon Helper DLL at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int identified = 0;

		identified += CheckKey({ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell" }, L"explorer.exe", reaction);
		identified += CheckKey({ HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell" }, L"explorer.exe", reaction);
		identified += CheckKey({ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell"}, L"", reaction);
		identified += CheckKey({ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit" }, 
			std::vector<std::wstring>{ L"", L"C:\\Windows\\system32\\userinit.exe,", L"C:\\Windows\\system32\\userinit.exe" }, reaction);
		identified += CheckKey({ HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit"},
			std::vector<std::wstring>{ L"", L"C:\\Windows\\system32\\userinit.exe,", L"C:\\Windows\\system32\\userinit.exe" }, reaction);
		identified += CheckKey({ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit"}, L"", reaction);
		identified += CheckForSubkeys({ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify" }, reaction);

		reaction.EndHunt();
		return identified;
	}

}