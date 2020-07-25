#include "mitigation/mitigations/MitigateV73511.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

using namespace Registry;

namespace Mitigations {

	MitigateV73511::MitigateV73511() :
		Mitigation(
			L"V-73511 - Command line data must be included in process creation events",
			L"Maintaining an audit trail of system activity logs can help identify configuration "
			"errors, troubleshoot service disruptions, and analyze compromises that have occurred, "
			"as well as detect attacks. Collecting this data is essential for analyzing the security "
			"of information assets and detecting signs of suspicious and unexpected behavior.",
			L"evt",
			SoftwareAffected::InternalService,
			MitigationSeverity::Medium
		) {}

	bool MitigateV73511::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(1, "Checking for presence of " << name);

		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" };
		std::wstring value = L"ProcessCreationIncludeCmdLine_Enabled";

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

	bool MitigateV73511::EnforceMitigation(SecurityLevel level) {
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" };
		std::wstring value = L"ProcessCreationIncludeCmdLine_Enabled";
		DWORD data = 1;

		LOG_VERBOSE(1, L"Attempting to set " << value << L" to 1.");
		return key.SetValue<DWORD>(value, data);
	}

	bool MitigateV73511::MitigationApplies(){
		return true;
	}
}