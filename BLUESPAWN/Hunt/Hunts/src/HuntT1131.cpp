#include "hunts/HuntT1131.h"
#include "hunts/RegistryHunt.hpp"

#include "logging/Log.h"
#include "configuration/Registry.h"

using namespace Registry;

namespace Hunts {
	HuntT1131::HuntT1131(HuntRegister& record) : Hunt(record) {
		dwSupportedScans = Aggressiveness::Cursory;
		dwStuffAffected = AffectedThing::Configurations;
		dwSourcesInvolved = DataSource::Registry;
		dwTacticsUsed = Tactic::Persistence;
	}

	int HuntT1131::ScanCursory(Scope& scope, Reaction* reaction){
		LOG_INFO("Hunting for T1131 - Authentication Package at level Cursory");

		int identified = 0;

		identified += CheckKey({ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Authentication Packages" }, okAuthPackages, reaction);
		identified += CheckKey({ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Notification Packages" }, okNotifPackages, reaction);
		
		return identified;
	}

}