#include "hunt/hunts/HuntT1101.h"
#include "hunt/RegistryHunt.hpp"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"

using namespace Registry;

namespace Hunts {
	HuntT1101::HuntT1101(HuntRegister& record) : Hunt(record, L"T1101 - Security Support Provider") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	int HuntT1101::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for T1101 - Security Support Provider at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int identified = 0;

		identified += CheckKey({ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Security Packages" }, okSecPackages, reaction);
		identified += CheckKey({ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig", L"Security Packages" }, okSecPackages, reaction);
		
		reaction.EndHunt();
		return identified;
	}

}