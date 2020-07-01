#include "mitigation/mitigations/MitigateV72753.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include <VersionHelpers.h>

using namespace Registry;

namespace Mitigations {

	MitigateV72753::MitigateV72753() : 
		Mitigation(
			L"V-72753 - WDigest Authentication must be disabled",
			L"When the WDigest Authentication protocol is enabled, plain text passwords are stored in the Local Security Authority"
			"Subsystem Service (LSASS) exposing them to theft. This setting will prevent WDigest from storing credentials in memory.",
			L"lsa",
			SoftwareAffected::OperatingSystem,
			MitigationSeverity::High
		) {}

	bool MitigateV72753::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(1, "Checking for presence of " << name);

		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest" };
		std::wstring value = L"UseLogonCredential";

		if(IsWindowsVersionOrGreater(6, 2, 0)){ // Win 8.1+
			if(!key.ValueExists(value)){
				return true;
			}
		} else if(!key.ValueExists(value)){
			return false;
		}

		if(key.GetValue<DWORD>(value) == 1){
			if(level == SecurityLevel::Low){
				LOG_INFO(1, L"[" + name + L"] Mitigation is not being enforced due to low security level.");
				return true;
			}
			return false;
		}
		return true;
	}

	bool MitigateV72753::EnforceMitigation(SecurityLevel level) {
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest" };
		std::wstring value = L"UseLogonCredential";
		DWORD data = 0;

		if (!IsWindowsVersionOrGreater(6, 2, 0) || key.ValueExists(value)) {
			return key.SetValue<DWORD>(value, data);
		}

		return true;
	}

	bool MitigateV72753::MitigationApplies(){
		return IsWindowsVersionOrGreater(6, 0, 0); // Win 7+
	}
}