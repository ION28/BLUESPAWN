#include "hunts/HuntT1037.h"
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

		typedef struct _KeyValuePairing {
			RegistryKey key;
			std::wstring value;
		} KeyValuePairing;

		KeyValuePairing pKeyValuePair = { 
			{HKEY_CURRENT_USER,L"Environment",L"UserInitMprLogonScript"}, L"" };

		int identified = 0;
		if (!(pKeyValuePair.key == pKeyValuePair.value)) {
			identified++;

			reaction->RegistryKeyIdentified(pKeyValuePair.key);
		}

		return identified;
	}

}