#include "hunts/HuntT1103.h"
#include "hunts/RegistryHunt.hpp"
#include "logging/Log.h"
#include "configuration/Registry.h"

using namespace Registry;

namespace Hunts {
	HuntT1103::HuntT1103(HuntRegister& record) : Hunt(record) {
		dwSupportedScans = Aggressiveness::Cursory;
		dwStuffAffected = AffectedThing::Configurations | AffectedThing::Processes;
		dwSourcesInvolved = DataSource::Registry;
		dwTacticsUsed = Tactic::Persistence | Tactic::PrivilegeEscalation;
	}

	int HuntT1103::ScanCursory(Scope& scope, Reaction* reaction){
		LOG_INFO("Hunting for T1103 - AppInit DLLs at level Cursory");

		int identified = 0;

		identified += CheckKey<REG_SZ_T>({ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs" }, L"", reaction);
		identified += CheckKey<REG_SZ_T>({ HKEY_LOCAL_MACHINE,L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs" }, L"", reaction);
		identified += CheckKey<REG_DWORD_T>({ HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"LoadAppInit_DLLs" }, 0, reaction);
		identified += CheckKey<REG_DWORD_T>({ HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"LoadAppInit_DLLs" }, 0, reaction);

		return identified;
	}

}