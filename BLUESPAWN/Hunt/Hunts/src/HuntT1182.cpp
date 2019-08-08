#include "hunts/HuntT1182.h"
#include "hunts/RegistryHunt.hpp"

#include "logging/Log.h"
#include "configuration/Registry.h"

using namespace Registry;

namespace Hunts {
	HuntT1182::HuntT1182(HuntRegister& record) : Hunt(record) {
		dwSupportedScans = Aggressiveness::Cursory;
		dwStuffAffected = AffectedThing::Configurations;
		dwSourcesInvolved = DataSource::Registry;
		dwTacticsUsed = Tactic::Persistence | Tactic::PrivilegeEscalation;
	}

	int HuntT1182::ScanCursory(Scope& scope, Reaction* reaction){
		LOG_INFO("Hunting for T1182 - AppCert DLLs at level Cursory");

		int identified = 0;

		identified += CheckForSubkeys(RegistryKey(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls"), reaction);
		
		return identified;
	}

}