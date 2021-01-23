#include "mitigation/mitigations/MitigateV3344.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

using namespace Registry;

namespace Mitigations{

	MitigateV3344::MitigateV3344() :
		Mitigation(
			L"V-3344 - Local accounts with blank passwords restricted to console logon only",
			L"This is a Category 1 finding because no accounts with blank passwords should exist on a system. "
			"The password policy should prevent this from occurring. However, if a local account with a blank "
			"password does exist, enabling this setting will limit the account to local console logon only.",
			L"lsa",
			SoftwareAffected::ExposedService,
			MitigationSeverity::High
		) {}

	bool  LimitBlankPasswordUse(bool enforce){
		auto lsa = RegistryKey{ HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Lsa" };
		if(!lsa.ValueExists(L"LimitBlankPasswordUse") || lsa.GetValue<DWORD>(L"LimitBlankPasswordUse") != 1){
			if(enforce){
				LOG_VERBOSE(1, "Setting LimitBlankPasswordUse to 1");
				return lsa.SetValue<DWORD>(L"LimitBlankPasswordUse", 1);
			} else {
				LOG_VERBOSE(1, "Detected LSA allowing non-console logons with blank passwords");
				return false;
			}
		}
		LOG_VERBOSE(1, "LSA is denying non-console logons with blank passwords");
		return true;
	}

	bool MitigateV3344::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(1, "Checking for presence of " << name);

		return  LimitBlankPasswordUse(false);
	}

	bool MitigateV3344::EnforceMitigation(SecurityLevel level) {
		LOG_INFO(1, "Enforcing Mitigation for " << name);

		return  LimitBlankPasswordUse(level >= SecurityLevel::Medium);
	}

	bool MitigateV3344::MitigationApplies(){
		return true;
	}
}
