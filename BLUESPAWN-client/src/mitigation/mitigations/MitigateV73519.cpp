#include "mitigation/mitigations/MitigateV73519.h"

#include "hunt/RegistryHunt.h"
#include "util/configurations/Registry.h"
#include "util/log/Log.h"
#include <algorithm>

using namespace Registry;

namespace Mitigations{

	MitigateV73519::MitigateV73519() :
		Mitigation(
			L"V-73519 - The Server Message Block (SMB) v1 protocol must be disabled on the SMB server",
			L"SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a "
			L"number of attacks such as collision and preimage attacks as well as not being FIPS compliant. Disabling SMBv1 "
			L"support may prevent access to file or print sharing resources with systems or devices that only support SMBv1. "
			"File shares and print services hosted on Windows Server 2003 are an example, however Windows Server 2003 is no "
			"longer a supported operating system. Some older network attached devices may only support SMBv1.",
			L"lanmanserver",
			SoftwareAffected::ExposedService,
			MitigationSeverity::Medium
		) {}

	bool CheckSMBv1(bool enforce){
		auto lanmankey = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" };
		if(!lanmankey.ValueExists(L"SMB1") || lanmankey.GetValue<DWORD>(L"SMB1") != 0){
			LOG_VERBOSE(1, L"SMBv1 has been detected.");
			if(enforce){
				LOG_VERBOSE(1, L"Disabling SMBv1... Restart required");
				return lanmankey.SetValue<DWORD>(L"SMB1", 0);
			}
			return false;
		}
		LOG_VERBOSE(1, "SMBv1 not detected");
		return true;
	}

	bool MitigateV73519::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(1, "Checking for presence of " << name);

		return CheckSMBv1(false);
	}

	bool MitigateV73519::EnforceMitigation(SecurityLevel level) {
		LOG_INFO(1, "Enforcing Mitigation for " << name);

		return CheckSMBv1(level >= SecurityLevel::Medium);
	}

	bool MitigateV73519::MitigationApplies(){
		auto lanmankey = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer" };
		return lanmankey.Exists() && lanmankey.ValueExists(L"Start") && *lanmankey.GetValue<DWORD>(L"Start") != 4;
	}
}