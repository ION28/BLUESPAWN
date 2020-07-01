#include "mitigation/mitigations/MitigateM1054-RDP.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

using namespace Registry;
namespace Mitigations {
	MitigateM1054RDP::MitigateM1054RDP() :
		Mitigation(
			L"M1054-RDP - Software Configuration (RDP)",
			L"This is a Medium severity finding as remote administrators should not have privilege "
			"other console users for access to a machine in most environments.",
			L"rdp",
			SoftwareAffected::ExposedService,
			MitigationSeverity::Medium
		) {}

	bool MitigateM1054RDP::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(1, "Checking for presence of " << name);

		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" };
		std::wstring value = L"fDisableForcibleLogoff";

		if (!key.ValueExists(value)) {
			LOG_VERBOSE(1, L"Value for " << value << L" does not exist.");
			return false;
		}

		if (key.GetValue<DWORD>(value) != 1) {
			LOG_VERBOSE(1, L"Value for " << value << L" is not set to 1.");
			return false;
		}

		LOG_VERBOSE(1, L"Mitigation " << name << L" is enforced.");
		return true;
	}

	bool MitigateM1054RDP::EnforceMitigation(SecurityLevel level) {
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" };
		std::wstring value = L"fDisableForcibleLogoff";
		DWORD data = 1;

		LOG_VERBOSE(1, L"Attempting to set " << value << L" to 1.");
		return key.SetValue<DWORD>(value, data);
	}

	bool MitigateM1054RDP::MitigationApplies() {
		return true;
	}
}
