#include "mitigation/mitigations/MitigateV71769.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include <VersionHelpers.h>

using namespace Registry;

namespace Mitigations {

	MitigateV71769::MitigateV71769() :
		Mitigation(
			L"V-71769 - Remote calls to the Security Account Manager (SAM) must be restricted to Administrators",
			L"The Windows Security Account Manager (SAM) stores users' passwords. Restricting remote rpc "
			"connections to the SAM to Administrators helps protect those credentials.",
			L"sam",
			SoftwareAffected::ExposedService,
			MitigationSeverity::Medium
		) {}

	bool MitigateV71769::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(1, "Checking for presence of " << name);

		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" };
		std::wstring value = L"RestrictRemoteSAM";

		if (!key.ValueExists(value)) {
			LOG_VERBOSE(1, L"Value for " << value << L" does not exist.");
			return false;
		}

		if(key.GetValue<std::wstring>(value) != L"O:BAG:BAD:(A;;RC;;;BA)"){
			LOG_VERBOSE(1, L"Value for " << value << L" is not set to O:BAG:BAD:(A;;RC;;;BA).");
			return false;
		}

		LOG_VERBOSE(1, L"Mitigation " << name << L" is enforced.");
		return true;
	}

	bool MitigateV71769::EnforceMitigation(SecurityLevel level) {
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" };
		std::wstring value = L"RestrictRemoteSAM";
		std::wstring data = L"O:BAG:BAD:(A;;RC;;;BA)";

		LOG_VERBOSE(1, L"Attempting to set " << value << L" to O:BAG:BAD:(A;;RC;;;BA).");
		return key.SetValue<std::wstring>(value, data);
	}

	bool MitigateV71769::MitigationApplies(){
		return true;
	}
}