#include "mitigation/mitigations/MitigateM1025.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include <VersionHelpers.h>

using namespace Registry;

namespace Mitigations{

	MitigateM1025::MitigateM1025() :
		Mitigation(
			L"M1025 - Privileged Process Integrity",
			L"Protect processes with high privileges that can be used to interact with critical "
			"system components through use of protected process light, anti-process injection defenses, "
			"or other process integrity enforcement measures.",
			L"lsa",
			SoftwareAffected::ExposedService,
			MitigationSeverity::Medium
		) {}

	bool CheckLSARunAsPPL(bool enforce){
		auto lsa = RegistryKey{ HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Lsa" };
		if(!lsa.ValueExists(L"LmCompatibilityLevel") || lsa.GetValue<DWORD>(L"RunAsPPL") != 1){
			if(enforce){
				LOG_VERBOSE(1, "Setting RunAsPPL Compatibility Level to 1");
				return lsa.SetValue<DWORD>(L"RunAsPPL", 1);
			} else {
				LOG_VERBOSE(1, "Detected LSA to not be running as a PPL");
				return false;
			}
		}
		LOG_VERBOSE(1, "LSA is running as a PPL");
		return true;
	}

	bool MitigateM1025::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(1, "Checking for presence of " << name);

		return CheckLSARunAsPPL(false);
	}

	bool MitigateM1025::EnforceMitigation(SecurityLevel level) {
		LOG_INFO(1, "Enforcing Mitigation for " << name);

		return CheckLSARunAsPPL(level >= SecurityLevel::Medium);
	}

	bool MitigateM1025::MitigationApplies(){
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" };
		auto version = key.GetValue<std::wstring>(L"CurrentVersion");
		DWORD dwMajorVersion = _wtoi(version->substr(0, version->find(L".", 0)).c_str());
		DWORD dwMinorVersion = _wtoi(version->substr(version->find(L".", 0) + 1).c_str());
		return dwMajorVersion > 6 || (dwMajorVersion == 6 && dwMinorVersion >= 3);
	}
}