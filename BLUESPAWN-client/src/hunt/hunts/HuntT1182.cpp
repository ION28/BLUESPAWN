#include "hunt/hunts/HuntT1182.h"
#include "hunt/RegistryHunt.hpp"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"

using namespace Registry;

namespace Hunts {
	HuntT1182::HuntT1182(HuntRegister& record) : Hunt(record, L"T1182 - AppCert DLLs") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
	}

	int HuntT1182::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for T1182 - AppCert DLLs at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int identified = 0;

		identified += CheckForSubkeys(RegistryKey(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls"), reaction);
		
		reaction.EndHunt();
		return identified;
	}

}