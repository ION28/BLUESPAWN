#include "mitigation/mitigations/MitigateM1042-LLMNR.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include <VersionHelpers.h>

using namespace Registry;

namespace Mitigations {

	MitigateM1042LLMNR::MitigateM1042LLMNR() :
		Mitigation(
			L"M1042-LLMNR - Link-Local Multicast Name Resolution (LLMNR) should be disabled",
			L"Link-Local Multicast Name Resolution (LLMNR) serve as alternate methods for "
			"host identification. Adversaries can spoof an authoritative source for name "
			"resolution on a victim network by responding to LLMNR (UDP 5355)/NBT-NS (UDP 137) "
			"traffic as if they know the identity of the requested host.",
			L"llmnr",
			SoftwareAffected::ExposedService,
			MitigationSeverity::Low
		) {}

	bool MitigateM1042LLMNR::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(1, "Checking for presence of " << name);

		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" };
		std::wstring value = L"EnableMulticast";

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

	bool MitigateM1042LLMNR::EnforceMitigation(SecurityLevel level) {
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" };
		std::wstring value = L"EnableMulticast";
		DWORD data = 0;

		LOG_VERBOSE(1, L"Attempting to set " << value << L" to 0.");
		return key.SetValue<DWORD>(value, data);
	}

	bool MitigateM1042LLMNR::MitigationApplies(){
		return true;
	}
}