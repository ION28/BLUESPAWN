#include "hunts/HuntT1037.h"
#include "hunts/RegistryHunt.hpp"

#include "logging/Log.h"

using namespace Registry;

namespace Hunts {
	HuntT1037::HuntT1037(HuntRegister& record) : Hunt(record) {
		dwSupportedScans = Aggressiveness::Cursory;
		dwStuffAffected = AffectedThing::Configurations;
		dwSourcesInvolved = DataSource::Registry;
		dwTacticsUsed = Tactic::Persistence | Tactic::LateralMovement;
	}

	int HuntT1037::ScanCursory(Scope& scope, Reaction* reaction){
		LOG_INFO("Hunting for T1037 - Logon Scripts at level Cursory");

		int identified = 0;

		identified += CheckKey({ HKEY_CURRENT_USER,L"Environment",L"UserInitMprLogonScript" }, L"", reaction);

		return identified;
	}

}