#include "mitigation/mitigations/MitigateV63597.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include <VersionHelpers.h>

using namespace Registry;

namespace Mitigations {

	MitigateV63597::MitigateV63597() :
		Mitigation(
			L"V-63597 - Apply UAC privileged token filtering for network logons",
			L"With User Account Control enabled, filtering the privileged token for built-in "
			"administrator accounts will prevent the elevated privileges of these accounts "
			"from being used over the network.",
			L"uac",
			SoftwareAffected::OperatingSystem,
			MitigationSeverity::Medium
		) {}

	bool MitigateV63597::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(1, "Checking for presence of " << name);

		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" };
		std::wstring value = L"LocalAccountTokenFilterPolicy";

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

	bool MitigateV63597::EnforceMitigation(SecurityLevel level) {
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" };
		std::wstring value = L"LocalAccountTokenFilterPolicy";
		DWORD data = 0;

		LOG_VERBOSE(1, L"Attempting to set " << value << L" to 0.");
		return key.SetValue<DWORD>(value, data);
	}

	bool MitigateV63597::MitigationApplies(){
		return true;
	}
}