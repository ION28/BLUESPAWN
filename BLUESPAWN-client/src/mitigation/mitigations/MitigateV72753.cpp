#include "mitigation/mitigations/MitigateV72753.h"
#include "hunt/RegistryHunt.hpp"

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

		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest", L"UseLogonCredential" };

		if(IsWindows8Point1OrGreater()){
			if(!key.ValueExists()){
				return true;
			}
		} else if(!key.ValueExists()){
			return false;
		}

		if(key.Get<DWORD>() == 1){
			if(level == SecurityLevel::Low){
				LOG_INFO("[V-72753 - WDigest Authentication must be disabled] Mitigation is not being enforced due to low security level.");
				return true;
			}
			return false;
		}
		return true;
	}

	bool MitigateV72753::EnforceMitigation(SecurityLevel level) {
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest", L"UseLogonCredential" };
		if(!IsWindows8Point1OrGreater() && !key.ValueExists()){
			DWORD value = 0;
			return key.Create(&value, 4, REG_DWORD);
		}

		return key.Set<DWORD>(0);
	}

	bool MitigateV72753::MitigationApplies(){
		return IsWindows7OrGreater();
	}
}