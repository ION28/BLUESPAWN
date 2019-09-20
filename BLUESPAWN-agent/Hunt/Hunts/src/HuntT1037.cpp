#include "hunts/HuntT1037.h"
#include "hunts/RegistryHunt.hpp"

#include "logging/Log.h"

using namespace Registry;

namespace Hunts {
	HuntT1037::HuntT1037(HuntRegister& record) : Hunt(record, L"T1037 - Logon Scripts") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::LateralMovement;
	}

	int HuntT1037::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for T1037 - Logon Scripts at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int identified = 0;

		identified += CheckKey({ HKEY_CURRENT_USER, L"Environment", L"UserInitMprLogonScript" }, L"", reaction);

		reaction.EndHunt();
		return identified;
	}

}