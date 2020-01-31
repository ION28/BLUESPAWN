#include "mitigation/mitigations/MitigateV72753.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include <VersionHelpers.h>

using namespace Registry;

namespace Mitigations {

	MitigateV72753::MitigateV72753(MitigationRegister& record) : 
		Mitigation(
			record,
			L"V-72753 - WDigest Authentication must be disabled",
			L"When the WDigest Authentication protocol is enabled, plain text passwords are stored in the Local Security Authority"
			"Subsystem Service (LSASS) exposing them to theft. This setting will prevent WDigest from storing credentials in memory.",
			L"lsa",
			SoftwareAffected::OperatingSystem,
			MitigationSeverity::High
		) {}

	bool MitigateV72753::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO("Checking for presence of " << name);

		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest" };

		if(IsWindows8Point1OrGreater()){
			if(!key.ValueExists(L"UseLogonCredential")){
				return true;
			}
		} else if(!key.ValueExists(L"UseLogonCredential")){
			return false;
		}

		if(key.GetValue<DWORD>(L"UseLogonCredential") == 1){
			if(level == SecurityLevel::Low){
				LOG_INFO("[V-72753 - WDigest Authentication must be disabled] Mitigation is not being enforced due to low security level.");
				return true;
			}
			return false;
		}
		return true;
	}

	bool MitigateV72753::EnforceMitigation(SecurityLevel level) {
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest" };
		if(!IsWindows8Point1OrGreater() && !key.ValueExists(L"UseLogonCredential")){
			DWORD value = 0;
			return key.SetValue<DWORD>(L"UseLogonCredential", 0);
		}

		return true;
	}

	bool MitigateV72753::MitigationApplies(){
		return IsWindows7OrGreater();
	}
}