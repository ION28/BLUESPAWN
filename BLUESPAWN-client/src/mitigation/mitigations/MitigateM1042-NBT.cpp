#include "mitigation/mitigations/MitigateM1042-NBT.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include <VersionHelpers.h>

using namespace Registry;

namespace Mitigations {

	MitigateM1042NBT::MitigateM1042NBT() :
		Mitigation(
			L"M1042-NBT - NetBIOS Name Service (NBT-NS) should be disabled",
			L" NetBIOS Name Service (NBT-NS) serve as alternate methods for "
			"host identification. Adversaries can spoof an authoritative source for name "
			"resolution on a victim network by responding to LLMNR (UDP 5355)/NBT-NS (UDP 137) "
			"traffic as if they know the identity of the requested host.",
			L"nbt",
			SoftwareAffected::ExposedService,
			MitigationSeverity::Low
		) {}

	bool MitigateM1042NBT::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(1, "Checking for presence of " << name);

		auto base = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces" };
		std::wstring value = L"NetbiosOptions";

		for (auto key : base.EnumerateSubkeys()) {
			if (key.GetValue<DWORD>(value) != 2) {
				LOG_VERBOSE(1, L"Value for " << key << value << L" is not set to 2.");
				return false;
			}
		}

		LOG_VERBOSE(1, L"Mitigation " << name << L" is enforced.");
		return true;
	}

	bool MitigateM1042NBT::EnforceMitigation(SecurityLevel level) {
		auto base = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces" };
		std::wstring value = L"NetbiosOptions";
		DWORD data = 2;

		int failcount = 0;

		for (auto key : base.EnumerateSubkeys()) {
			if (key.GetValue<DWORD>(value) != 2) {
				LOG_VERBOSE(1, L"Attempting to set " << key << value << L" to 2.");
				if (!key.SetValue<DWORD>(value, data)) {
					LOG_VERBOSE(1, L"Unable to set " << key << value << L" to 2.");
					failcount++; 
				}
			}
		}

		if (failcount == 0) {
			LOG_VERBOSE(1, L"Mitigation " << name << L" is enforced.");
			return true;
		}
		else {
			LOG_VERBOSE(1, L"Failed to enforce " << failcount << L" values for Mitigation " << name);
			return false;
		}
	}

	bool MitigateM1042NBT::MitigationApplies(){
		return true;
	}
}