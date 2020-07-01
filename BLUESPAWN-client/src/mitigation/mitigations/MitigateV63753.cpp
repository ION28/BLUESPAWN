#include "mitigation/mitigations/MitigateV63753.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

using namespace Registry;

namespace Mitigations {

	MitigateV63753::MitigateV63753() :
		Mitigation(
			L"V-63753 - Prevent the storage of passwords and credentials used for Network Authentication",
			L"This setting controls the storage of passwords and credentials for network authentication "
			"on the local system. Such credentials must not be stored on the local machine as that may "
			"lead to account compromise. This setting refers primarily to Domain Credentials.",
			L"lsa",
			SoftwareAffected::OperatingSystem,
			MitigationSeverity::Medium
		) {}

	bool MitigateV63753::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(1, "Checking for presence of " << name);

		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" };
		std::wstring value = L"DisableDomainCreds";

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

	bool MitigateV63753::EnforceMitigation(SecurityLevel level) {
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" };
		std::wstring value = L"DisableDomainCreds";
		DWORD data = 1;

		LOG_VERBOSE(1, L"Attempting to set " << value << L" to 1.");
		return key.SetValue<DWORD>(value, data);
	}

	bool MitigateV63753::MitigationApplies(){
		return true;
	}
}