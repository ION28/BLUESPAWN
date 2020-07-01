#include "mitigation/mitigations/MitigateV73585.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include <VersionHelpers.h>

using namespace Registry;

namespace Mitigations {

	MitigateV73585::MitigateV73585() :
		Mitigation(
			L"V-73585 - The Windows Installer Always install with elevated privileges option must be disabled",
			L"Standard user accounts must not be granted elevated privileges. Enabling Windows Installer to elevate "
			"privileges when installing applications can allow malicious persons and applications to gain full "
			"control of a system.",
			L"uac",
			SoftwareAffected::InternalService,
			MitigationSeverity::High
		) {}

	bool MitigateV73585::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(1, "Checking for presence of " << name);

		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" };
		std::wstring value = L"AlwaysInstallElevated";

		if (!key.ValueExists(value)) {
			LOG_VERBOSE(1, L"Value for " << value << L" does not exist.");
			return false;
		}

		if(key.GetValue<DWORD>(value) != 0){
			LOG_VERBOSE(1, L"Value for " << value << L" is not set to 0.");
			return false;
		}

		LOG_VERBOSE(1, L"Mitigation " << name << L" is enforced.");
		return true;
	}

	bool MitigateV73585::EnforceMitigation(SecurityLevel level) {
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" };
		std::wstring value = L"AlwaysInstallElevated";
		DWORD data = 0;

		if (!key.Exists()) {
			LOG_VERBOSE(1, "Key does not exist. Creating key and setting value to 0.");
			return key.Create() && key.SetValue<DWORD>(value, data);
		}

		LOG_VERBOSE(1, L"Attempting to set " << value << L" to 0.");

		return key.SetValue<DWORD>(value, data);
	}

	bool MitigateV73585::MitigationApplies(){
		return true;
	}
}