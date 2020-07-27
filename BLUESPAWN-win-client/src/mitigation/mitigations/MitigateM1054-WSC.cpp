#include "mitigation/mitigations/MitigateM1054-WSC.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

using namespace Registry;

namespace Mitigations {

	MitigateM1054WSC::MitigateM1054WSC() :
		Mitigation(
			L"M1054-WSC - Windows Security Center provides appropriate security alerts",
			L"The Windows Security Center provides warnings on basic security settings",
			L"wsc",
			SoftwareAffected::OperatingSystem,
			MitigationSeverity::Low
		) {}

	bool MitigateM1054WSC::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(1, "Checking for presence of " << name);

		auto WindowsSecurityCenter = RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Security Center" };
		auto WindowsSecurityCenterWow64 = RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Security Center" };

		for (auto key : { WindowsSecurityCenter, WindowsSecurityCenterWow64 }) {
			if (!key.ValueExists(L"AntiSpyWareDisableNotify") || key.GetValue<DWORD>(L"AntiSpyWareDisableNotify") != 0) {
				LOG_VERBOSE(1, L"Value for AntiSpyWareDisableNotify is not set to 0 for " << key.ToString());
				return false;
			}
			if (!key.ValueExists(L"AntiVirusDisableNotify") || key.GetValue<DWORD>(L"AntiVirusDisableNotify") != 0) {
				LOG_VERBOSE(1, L"Value for AntiVirusDisableNotify is not set to 0 for " << key.ToString());
				return false;
			}
			if (!key.ValueExists(L"UacDisableNotify") || key.GetValue<DWORD>(L"UacDisableNotify") != 0) {
				LOG_VERBOSE(1, L"Value for UacDisableNotify is not set to 0 for " << key.ToString());
				return false;
			}
			if (!key.ValueExists(L"FirewallDisableNotify") || key.GetValue<DWORD>(L"FirewallDisableNotify") != 0) {
				LOG_VERBOSE(1, L"Value for FirewallDisableNotify is not set to 0 for " << key.ToString());
				return false;
			}
		}

		LOG_VERBOSE(1, L"Mitigation " << name << L" is enforced.");
		return true;
	}

	bool MitigateM1054WSC::EnforceMitigation(SecurityLevel level) {
		auto WindowsSecurityCenter = RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Security Center" };
		auto WindowsSecurityCenterWow64 = RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Security Center" };

		for (auto key : { WindowsSecurityCenter, WindowsSecurityCenterWow64 }) {
			LOG_VERBOSE(1, L"Attempting to set AntiSpyWareDisableNotify to 0 for " << key.ToString());
			if (!key.SetValue<DWORD>(L"AntiSpyWareDisableNotify", 0)) {
				return false;
			}

			LOG_VERBOSE(1, L"Attempting to set AntiVirusDisableNotify to 0 for " << key.ToString());
			if (!key.SetValue<DWORD>(L"AntiVirusDisableNotify", 0)) {
				return false;
			}

			LOG_VERBOSE(1, L"Attempting to set UacDisableNotify to 0 for " << key.ToString());
			if (!key.SetValue<DWORD>(L"UacDisableNotify", 0)) {
				return false;
			}

			LOG_VERBOSE(1, L"Attempting to set FirewallDisableNotify to 0 for " << key.ToString());
			if (!key.SetValue<DWORD>(L"FirewallDisableNotify", 0)) {
				return false;
			}
		}

		return true;
	}

	bool MitigateM1054WSC::MitigationApplies(){
		return true;
	}
}