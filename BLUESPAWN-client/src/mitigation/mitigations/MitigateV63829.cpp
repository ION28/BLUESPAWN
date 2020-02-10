#include "mitigation/mitigations/MitigateV63829.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include <VersionHelpers.h>

using namespace Registry;

namespace Mitigations {

	MitigateV63829::MitigateV63829() :
		Mitigation(
			L"V-63829 - User Account Control must run all administrators in Admin Approval Mode, enabling UAC",
			L"User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, "
			"including administrative accounts, unless authorized. This setting enables UAC.",
			L"uac",
			SoftwareAffected::OperatingSystem,
			MitigationSeverity::Medium
		) {}

	bool MitigateV63829::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO("Checking for presence of " << name);

		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" };
		std::wstring value = L"EnableLUA";

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

	bool MitigateV63829::EnforceMitigation(SecurityLevel level) {
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" };
		std::wstring value = L"EnableLUA";
		DWORD data = 1;

		LOG_VERBOSE(1, L"Attempting to set " << value << L" to 1.");
		return key.SetValue<DWORD>(value, data);
	}

	bool MitigateV63829::MitigationApplies(){
		return true;
	}
}