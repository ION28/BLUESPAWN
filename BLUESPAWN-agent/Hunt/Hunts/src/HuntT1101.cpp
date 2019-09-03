#include "hunts/HuntT1101.h"
#include "hunts/RegistryHunt.hpp"

#include "logging/Log.h"
#include "configuration/Registry.h"

using namespace Registry;

namespace Hunts {
	HuntT1101::HuntT1101(HuntRegister& record) : Hunt(record) {
		dwSupportedScans = Aggressiveness::Cursory;
		dwStuffAffected = AffectedThing::Configurations;
		dwSourcesInvolved = DataSource::Registry;
		dwTacticsUsed = Tactic::Persistence;
	}

	int HuntT1101::ScanCursory(Scope& scope, Reaction* reaction){
		LOG_INFO("Hunting for T1101 - Security Support Provider at level Cursory");

		int identified = 0;

		identified += CheckKey({ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Security Packages" }, okSecPackages, reaction);
		identified += CheckKey({ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig", L"Security Packages" }, okSecPackages, reaction);
		
		return identified;
	}

}