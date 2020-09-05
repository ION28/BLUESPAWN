#include "mitigation/mitigations/MitigateV3379.h"

#include "hunt/RegistryHunt.h"
#include "util/configurations/Registry.h"
#include "util/log/Log.h"

using namespace Registry;

namespace Mitigations{

	MitigateV3379::MitigateV3379() :
		Mitigation(
			L"V-3379 - The system is configured to store the LAN Manager hash of the password in the SAM",
			L"This setting controls whether or not a LAN Manager hash of the password is stored in the SAM "
			"the next time the password is changed. The LAN Manager hash uses a weak encryption algorithm and "
			"there are several tools available that use this hash to retrieve account passwords",
			L"lsa",
			SoftwareAffected::InternalService,
			MitigationSeverity::High
		) {}

	bool CheckNoLMHash(bool enforce){
		auto lsa = RegistryKey{ HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Lsa" };
		if(!lsa.ValueExists(L"NoLMHash") || lsa.GetValue<DWORD>(L"NoLMHash") != 1){
			if(enforce){
				LOG_VERBOSE(1, "Setting NoLMHash to 1 (Don't store hashes)");
				return lsa.SetValue<DWORD>(L"NoLMHash", 1);
			} else {
				LOG_VERBOSE(1, "Detected misconfigured NoLMHash value");
				return false;
			}
		}
		LOG_VERBOSE(1, "NoLMHash is correctly set");
		return true;
	}

	bool MitigateV3379::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(1, "Checking for presence of " << name);

		return CheckNoLMHash(false);
	}

	bool MitigateV3379::EnforceMitigation(SecurityLevel level) {
		LOG_INFO(1, "Enforcing Mitigation for " << name);

		return CheckNoLMHash(level >= SecurityLevel::Medium);
	}

	bool MitigateV3379::MitigationApplies(){
		return true;
	}
}