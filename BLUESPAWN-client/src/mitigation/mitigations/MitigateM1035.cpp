#include "mitigation/mitigations/MitigateM1035.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

using namespace Registry;
namespace Mitigations {
	MitigateM1035::MitigateM1035() :
		Mitigation(
			L"M-1035 Limit Access to Resource over Network.",
			L"This is a High severity finding due to the Bluekeep vulnerability that allows for a worm to quickly move through "
				"a network when NLA is disabled. RDP is a service that allows remote access to Windows computers. Network Level "
				"Authentication or NLA requires that any user attempting to RDP to this computer to authenticate with the network "
				"before making contact.",
			SoftwareAffected::ExposedService,
			MitigationSeverity::High
		) {}

	bool MitigateM1035::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(L"Checking for presence of " << name);

		auto key = RegistryKey{ HKLM, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" };
		if (key.ValueExists(L"UserAuthentication")) {
			auto value = *key.GetValue<DWORD>(L"UserAuthentication");
			if (value == 1) {
				LOG_VERBOSE(1, "NLA is enabled for RDP.")''
				return true;
			}
		}
		LOG_VERBOSE(1, "NLA is disabled for RDP.");
		return false;
	}

	bool MitigateM1035::EnforceMitigation(SecurityLevel level) {
		LOG_INFO(L"Enforcing mitigation " << name);
		auto key = RegistryKey{ HKLM, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" };
		if (key.SetValue<DWORD>(L"UserAuthentication", 1)) {
			LOG_VERBOSE(1, "NLA successfully enabled for RDP.");
			return true;
		}
		else {
			LOG_VERBOSE(1, "Unable to enable NLA for RDP");
			return false;
		}
	}

	bool MitigateM1035::MitigationApplies() {
		return true;
	}
}
