#include "mitigation/mitigations/MitigateV3344.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include <VersionHelpers.h>

using namespace Registry;

namespace Mitigations{

	MitigateV3344::MitigateV3344() :
		Mitigation(
			L"V3344 - Local accounts with blank passwords restricted to console logon only",
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
				return lsa.SetValue<DWORD>(L"RunAsPPL", 1);
			} else {
				LOG_VERBOSE(1, "Detected LSA allowing blank passwords");
				return false;
			}
		}
		LOG_VERBOSE(1, "LSA is limiting blank passwords");
		return true;
	}

	bool MitigateV3344::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO("Checking for presence of " << name);

		return  LimitBlankPasswordUse(false);
	}

	bool MitigateV3344::EnforceMitigation(SecurityLevel level) {
		LOG_INFO("Enforcing Mitigation for " << name);

		return  LimitBlankPasswordUse(level >= SecurityLevel::Medium);
	}

	bool MitigateV3344::MitigationApplies(){
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" };
		auto version = key.GetValue<std::wstring>(L"CurrentVersion");
		DWORD dwMajorVersion = _wtoi(version->substr(0, version->find(L".", 0)).c_str());
		DWORD dwMinorVersion = _wtoi(version->substr(version->find(L".", 0) + 1).c_str());
		return dwMajorVersion > 6 || (dwMajorVersion == 6 && dwMinorVersion >= 3);
	}
}