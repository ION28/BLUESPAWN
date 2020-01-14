#include "mitigation/mitigations/MitigateV3338.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

using namespace Registry;

namespace Mitigations {

	MitigateV3338::MitigateV3338(MitigationRegister& record) : 
		Mitigation(
			record,
			L"V-3338 - Unauthorized named pipes are accessible with anonymous credentials.",
			L"This is a High finding because of the potential for gaining unauthorized system access. Pipes are internal system communications processes. "
				"They are identified internally by ID numbers that vary between systems. To make access to these processes easier, these pipes are given names "
				"that do not vary between systems. This setting controls which of these pipes anonymous users may access.",
			L"lanmanserver",
			SoftwareAffected::ExposedService,
			MitigationSeverity::High
		) {}

	bool MitigateV3338::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO("Checking for presence of " << name);
		
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\LanManServer\\Parameters", L"NullSessionPipes" };
		if(key.ValueExists()){
			auto values = key.Get<REG_MULTI_SZ_T>();
			for(auto value : values){
				if(value.size() != 0){ // TODO: Add exceptions on domain controllers
					return false;
				}
			}
		} 
		
		return true;
	}

	bool MitigateV3338::EnforceMitigation(SecurityLevel level) {
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\LanManServer\\Parameters", L"NullSessionPipes" };
		if(key.ValueExists()){
			auto values = key.Get<REG_MULTI_SZ_T>();
			auto vGoodValues = std::vector<std::wstring>{};
			for(auto value : values){
				if(value.size() == 0){ // TODO: Add exceptions on domain controllers
					vGoodValues.emplace_back(value);
				}
			}
			return key.Set<REG_MULTI_SZ_T>(vGoodValues);
		}

		return true;
	}

	bool MitigateV3338::MitigationApplies(){
		return true;
	}
}