#include "mitigation/mitigations/MitigateV3340.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

using namespace Registry;

namespace Mitigations {

	MitigateV3340::MitigateV3340() :
		Mitigation(
			L"V-3340 - Unauthorized shares can be accessed anonymously",
			L"This is a Category 1 finding because of the potential for gaining unauthorized "
			"system access. Any shares listed can be accessed by any network user. This could "
			"lead to the exposure or corruption of sensitive data.",
			L"lanmanserver",
			SoftwareAffected::ExposedService,
			MitigationSeverity::High
		) {}

	bool MitigateV3340::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(1, "Checking for presence of " << name);

		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters" };
		std::wstring value = L"NullSessionShares";

		auto values = *key.GetValue<std::vector<std::wstring>>(value);

		if(values.size() != 0){
			LOG_VERBOSE(1, L"Value for " << value << L" is not blank.");
			return false;
		}

		LOG_VERBOSE(1, L"Mitigation " << name << L" is enforced.");
		return true;
	}

	bool MitigateV3340::EnforceMitigation(SecurityLevel level) {
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters" };
		std::wstring value = L"NullSessionShares";
		auto data = std::vector<std::wstring>{};

		LOG_VERBOSE(1, L"Attempting to make " << value << L" blank.");
		return key.SetValue<std::vector<std::wstring>>(value, data);
	}

	bool MitigateV3340::MitigationApplies(){
		return true;
	}
}