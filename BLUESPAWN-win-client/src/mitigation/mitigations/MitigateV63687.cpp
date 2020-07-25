#include "mitigation/mitigations/MitigateV63687.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

using namespace Registry;

namespace Mitigations {

	MitigateV63687::MitigateV63687() :
		Mitigation(
			L"V-63687 - Caching of logon credentials must be limited",
			L"The default Windows configuration caches the last logon credentials for users who log on "
			"interactively to a system. This feature is provided for system availability reasons, such as "
			"the user's machine being disconnected from the network or domain controllers being unavailable. "
			"Even though the credential cache is well-protected, if a system is attacked, an unauthorized "
			"individual may isolate the password to a domain user account using a password-cracking program "
			"and gain access to the domain.",
			L"lsa",
			SoftwareAffected::OperatingSystem,
			MitigationSeverity::Low
		) {}

	bool MitigateV63687::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(1, "Checking for presence of " << name);

		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" };
		std::wstring value = L"CachedLogonsCount";

		if (!key.ValueExists(value)) {
			LOG_VERBOSE(1, L"Value for " << value << L" does not exist.");
			return false;
		}

		if(key.GetValue<DWORD>(value) > 1u){
			LOG_VERBOSE(1, L"Value for " << value << L" is greater than 1.");
			return false;
		}

		LOG_VERBOSE(1, L"Mitigation " << name << L" is enforced.");
		return true;
	}

	bool MitigateV63687::EnforceMitigation(SecurityLevel level) {
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" };
		std::wstring value = L"CachedLogonsCount";
		DWORD data = 1;

		LOG_VERBOSE(1, L"Attempting to set " << value << L" to 1.");
		return key.SetValue<DWORD>(value, data);
	}

	bool MitigateV63687::MitigationApplies(){
		return true;
	}
}
