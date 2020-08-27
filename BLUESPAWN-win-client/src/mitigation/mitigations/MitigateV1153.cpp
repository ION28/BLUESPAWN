#include "mitigation/mitigations/MitigateV1153.h"

#include "hunt/RegistryHunt.h"
#include "util/configurations/Registry.h"
#include "util/log/Log.h"
#include <algorithm>

using namespace Registry;

namespace Mitigations{

	MitigateV1153::MitigateV1153() :
		Mitigation(
			L"V-1153 - The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM",
			L"The Kerberos v5 authentication protocol is the default for authentication of users who are logging on to domain "
			L"accounts. NTLM which is less secure, is retained in later Windows versions for compatibility with clients and servers "
			L"that are running earlier versions of Windows or applications that still use it. It is also used to authenticate logons "
			L"to stand-alone computers that are running later versions.",
			L"lsa",
			SoftwareAffected::ExposedService,
			MitigationSeverity::Medium
		) {}

	bool CheckLMCompatibilityLevel(bool enforce){
		auto lsa = RegistryKey{ HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Lsa" };
		if(!lsa.ValueExists(L"LmCompatibilityLevel") || lsa.GetValue<DWORD>(L"LmCompatibilityLevel") != 5){
			if(enforce){
				LOG_VERBOSE(1, "Setting LM Compatibility Level to 5 (allow only NTLMv2)");
				return lsa.SetValue<DWORD>(L"LmCompatibilityLevel", 5);
			} else {
				LOG_VERBOSE(1, "Detected misconfigured LM Compatibility level");
				return false;
			}
		}
		LOG_VERBOSE(1, "LM Compatibility Level is correctly set");
		return true;
	}

	bool MitigateV1153::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(1, "Checking for presence of " << name);

		return CheckLMCompatibilityLevel(false);
	}

	bool MitigateV1153::EnforceMitigation(SecurityLevel level) {
		LOG_INFO(1, "Enforcing Mitigation for " << name);

		return CheckLMCompatibilityLevel(level >= SecurityLevel::Medium);
	}

	bool MitigateV1153::MitigationApplies(){
		return true;
	}
}