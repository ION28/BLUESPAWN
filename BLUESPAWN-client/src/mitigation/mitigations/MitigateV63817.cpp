#include "mitigation/mitigations/MitigateV63817.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include <VersionHelpers.h>

using namespace Registry;

namespace Mitigations {

	MitigateV63817::MitigateV63817() :
		Mitigation(
			L"V-63817 - User Account Control approval mode for the built-in Administrator must be enabled",
			L"User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, "
			"including administrative accounts, unless authorized. This setting configures the built-in "
			"Administrator account so that it runs in Admin Approval Mode.",
			L"uac",
			SoftwareAffected::OperatingSystem,
			MitigationSeverity::Medium
		) {}

	bool MitigateV63817::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(1, "Checking for presence of " << name);

		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" };
		std::wstring value = L"FilterAdministratorToken";

		if (!key.ValueExists(value)) {
			LOG_VERBOSE(1, L"Value for " << value << L" does not exist.");
			return false;
		}

		if(key.GetValue<DWORD>(value) != 1){
			LOG_VERBOSE(1, L"Value for " << value << L" is not set to 1.");
			return false;
		}

		LOG_VERBOSE(1, L"Mitigation " << name << L" is enforced.");
		return true;
	}

	bool MitigateV63817::EnforceMitigation(SecurityLevel level) {
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" };
		std::wstring value = L"FilterAdministratorToken";
		DWORD data = 1;

		LOG_VERBOSE(1, L"Attempting to set " << value << L" to 1.");
		return key.SetValue<DWORD>(value, data);
	}

	bool MitigateV63817::MitigationApplies(){
		return true;
	}
}