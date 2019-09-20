#include "hunts/HuntT1103.h"
#include "hunts/RegistryHunt.hpp"
#include "logging/Log.h"
#include "configuration/Registry.h"

using namespace Registry;

namespace Hunts {
	HuntT1103::HuntT1103(HuntRegister& record) : Hunt(record, L"T1103 - AppInit DLLs") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Processes;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
	}

	int HuntT1103::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for T1103 - AppInit DLLs at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int identified = 0;

		identified += CheckKey<REG_SZ_T>({ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs" }, L"", reaction);
		identified += CheckKey<REG_SZ_T>({ HKEY_LOCAL_MACHINE,L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs" }, L"", reaction);
		identified += CheckKey<REG_DWORD_T>({ HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"LoadAppInit_DLLs" }, 0, reaction);
		identified += CheckKey<REG_DWORD_T>({ HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"LoadAppInit_DLLs" }, 0, reaction);

		reaction.EndHunt();
		return identified;
	}

}