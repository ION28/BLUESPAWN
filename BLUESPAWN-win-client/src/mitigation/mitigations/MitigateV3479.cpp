#include "mitigation/mitigations/MitigateV3479.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

using namespace Registry;

namespace Mitigations {

	MitigateV3479::MitigateV3479() :
		Mitigation(
			L"V-3479 - The system will be configured to use Safe DLL Search Mode",
			L"The default search behavior, when an application calls a function in a Dynamic Link Library (DLL), "
			"is to search the current directory followed by the directories contained in the systems path environment "
			"variable. An unauthorized DLL inserted into an applications working directory could allow malicious code "
			"to be run on the system. Creating the following registry key and setting the appropriate value forces the "
			"system to search the %Systemroot% for the DLL before searching the current directory or the rest of the path.",
			L"smss",
			SoftwareAffected::OperatingSystem,
			MitigationSeverity::Medium
		) {}

	bool MitigateV3479::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(1, "Checking for presence of " << name);

		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager" };
		std::wstring value = L"SafeDllSearchMode";

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

	bool MitigateV3479::EnforceMitigation(SecurityLevel level) {
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager" };
		std::wstring value = L"SafeDllSearchMode";
		DWORD data = 1;

		LOG_VERBOSE(1, L"Attempting to set " << value << L" to 1.");
		return key.SetValue<DWORD>(value, data);
	}

	bool MitigateV3479::MitigationApplies(){
		return true;
	}
}
