#include "hunts/HuntT1138.h"
#include "hunts/RegistryHunt.hpp"

#include "logging/Log.h"
#include "configuration/Registry.h"

using namespace Registry;

namespace Hunts {
	HuntT1138::HuntT1138(HuntRegister& record) : Hunt(record, L"T1138 - Application Shimming") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
	}

	int HuntT1138::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for T1138 - Application Shimming at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int identified = 0;

		identified += CheckForSubkeys({ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB"}, reaction);
		identified += CheckForSubkeys({ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom"}, reaction);
		
		reaction.EndHunt();
		return identified;
	}

}