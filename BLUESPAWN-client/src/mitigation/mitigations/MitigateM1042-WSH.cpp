#include "mitigation/mitigations/MitigateM1042-WSH.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include <VersionHelpers.h>

using namespace Registry;

namespace Mitigations {

	MitigateM1042WSH::MitigateM1042WSH() :
		Mitigation(
			L"M1042-WSH - Windows Script Host (WSH) should be disabled",
			L"Windows Script Host enables the execution of wscript and cscript "
			"which allow VB, JS, and other scripts to be run. This feature is not "
			"typically needed, and Sean Metcalf recommends disabling it https://adsecurity.org/?p=3299. "
			"This corresponds to M1042.",
			L"wsh",
			SoftwareAffected::InternalService,
			MitigationSeverity::Low
		) {}

	bool MitigateM1042WSH::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO("Checking for presence of " << name);

		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows Script Host\\Settings" };
		std::wstring value = L"Enabled";

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

	bool MitigateM1042WSH::EnforceMitigation(SecurityLevel level) {
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows Script Host\\Settings" };
		std::wstring value = L"Enabled";
		DWORD data = 0;

		LOG_VERBOSE(1, L"Attempting to set " << value << L" to 0.");
		return key.SetValue<DWORD>(value, data);
	}

	bool MitigateM1042WSH::MitigationApplies(){
		return true;
	}
}