#include "mitigation/mitigations/MitigateV3338.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"
#include <algorithm>

using namespace Registry;

namespace Mitigations {

	MitigateV3338::MitigateV3338() : 
		Mitigation(
			L"V-3338 - Unauthorized named pipes are accessible with anonymous credentials",
			L"This is a High finding because of the potential for gaining unauthorized system access. Pipes are internal system communications processes. "
				"They are identified internally by ID numbers that vary between systems. To make access to these processes easier, these pipes are given names "
				"that do not vary between systems. This setting controls which of these pipes anonymous users may access.",
			L"lanmanserver",
			SoftwareAffected::ExposedService,
			MitigationSeverity::High
		) {}

	bool MitigateV3338::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(1, "Checking for presence of " << name);

		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\LanManServer\\Parameters" };
		if(key.ValueExists(L"NullSessionPipes")){
			auto values = *key.GetValue<std::vector<std::wstring>>(L"NullSessionPipes");
			auto vGoodValues = std::vector<std::wstring>{};
			for(auto value : values){
				if(value.size() == 0){ // TODO: Add exceptions on domain controllers (netlogon, samr, lsarpc)
					LOG_VERBOSE(1, "Found a non-zero number of named pipes accessible anonymously.");
					return false;
				}
			}
		}
		LOG_VERBOSE(1, "Found no named pipes accessible anonymously.");
		return true;
	}

	bool MitigateV3338::EnforceMitigation(SecurityLevel level) {
		LOG_INFO(1, "Enforcing Mitigation for " << name);
		
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\LanManServer\\Parameters" };
		if(key.ValueExists(L"NullSessionPipes")){
			auto values = *key.GetValue<std::vector<std::wstring>>(L"NullSessionPipes");
			/* TODO: Add prompt to ask if this is a domain controller */
			//auto vGoodValues = std::vector<std::wstring>{L"NETLOGON", L"SAMR", L"LSARPC"};
			auto vGoodValues = std::vector<std::wstring>{};
			for(auto value : values){
				if (std::find(vGoodValues.begin(), vGoodValues.end(), value) == vGoodValues.end()) {
					LOG_VERBOSE(1, L"Found a named pipe (" + value + L") that should not be allowed.");
				}
			}
			LOG_VERBOSE(2, L"Setting accessible named pipes to specified good values.");
			return key.SetValue<std::vector<std::wstring>>(L"NullSessionPipes", vGoodValues);
		}
		return true;
	}

	bool MitigateV3338::MitigationApplies(){
		return true;
	}
}