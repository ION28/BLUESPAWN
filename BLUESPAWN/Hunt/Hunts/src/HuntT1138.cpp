#include "hunts/HuntT1138.h"
#include "hunts/RegistryHunt.hpp"

#include "logging/Log.h"
#include "configuration/Registry.h"

using namespace Registry;

namespace Hunts {
	HuntT1138::HuntT1138(HuntRegister& record) : Hunt(record) {
		dwSupportedScans = Aggressiveness::Cursory;
		dwStuffAffected = AffectedThing::Configurations;
		dwSourcesInvolved = DataSource::Registry;
		dwTacticsUsed = Tactic::Persistence | Tactic::PrivilegeEscalation;
	}

	int HuntT1138::ScanCursory(Scope& scope, Reaction* reaction){
		LOG_INFO("Hunting for T1138 - Application Shimming at level Cursory");

		int identified = 0;

		identified += CheckKey({ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags", L"InstalledSDB" }, L"", reaction);
		identified += CheckKey({ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags", L"Custom" }, L"", reaction);
		
		return identified;
	}

}