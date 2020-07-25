#include "mitigation/mitigations/MitigateM1035-RDP.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"
using namespace Registry;
namespace Mitigations {
	MitigateM1035RDP::MitigateM1035RDP() :
		Mitigation(
			L"M1035-RDP - Limit Access to Resource over Network",
			L"This is a High severity finding due to the Bluekeep vulnerability that allows for a worm to quickly move through "
				"a network when NLA is disabled. RDP is a service that allows remote access to Windows computers.",
			L"RDP",
			SoftwareAffected::ExposedService,
			MitigationSeverity::High
		) {}

	bool MitigateM1035RDP::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(1, L"Checking for presence of " << name);

		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" };
		if (key.ValueExists(L"UserAuthentication")) {
			auto value = *key.GetValue<DWORD>(L"UserAuthentication");
			if (value == 1) {
				LOG_VERBOSE(1, "NLA is enabled for RDP.");
				return true;
			}
		}
		LOG_VERBOSE(1, "NLA is disabled for RDP.");
		return false;
	}

	bool MitigateM1035RDP::EnforceMitigation(SecurityLevel level) {
		LOG_INFO(1, L"Enforcing mitigation " << name);
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" };
		if (key.SetValue<DWORD>(L"UserAuthentication", 1)) {
			LOG_VERBOSE(1, "NLA successfully enabled for RDP.");
			return true;
		}
		else {
			LOG_VERBOSE(1, "Unable to enable NLA for RDP");
			return false;
		}
	}

	bool MitigateM1035RDP::MitigationApplies() {
		return true;
	}
}
