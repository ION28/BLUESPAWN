#include "hunt/hunts/HuntT1131.h"
#include "hunt/RegistryHunt.hpp"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"

using namespace Registry;

namespace Hunts {
	HuntT1131::HuntT1131(HuntRegister& record) : Hunt(record, L"T1131 - Authentication Package") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	int HuntT1131::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for T1131 - Authentication Package at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int identified = 0;

		identified += CheckKey({ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Authentication Packages" }, okAuthPackages, reaction);
		identified += CheckKey({ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Notification Packages" }, okNotifPackages, reaction);
		
		reaction.EndHunt();
		return identified;
	}

}