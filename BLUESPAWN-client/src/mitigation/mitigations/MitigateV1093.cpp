#include "mitigation/mitigations/MitigateV1093.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

using namespace Registry;

namespace Mitigations {

	MitigateV1093::MitigateV1093() :
		Mitigation(
			L"V-1093 - Anonymous enumeration of shares must be restricted",
			L"This is a High finding because allowing anonymous logon users (null session connections) to list all"
				"account names and enumerate all shared resources can provide a map of potential points to attack the system.",
			L"lsa",
			SoftwareAffected::ExposedService,
			MitigationSeverity::High
		) {}

	bool MitigateV1093::MitigationIsEnforced(SecurityLevel level) {
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Lsa" };
		auto data = key.GetValue<DWORD>(L"RestrictAnonymous");
		if(!data || !*data){
			LOG_INFO(1, L"[" + name + L"] RestrictAnonymous value is not set to 1");
			return false;
		}

		return true;
	}

	bool MitigateV1093::EnforceMitigation(SecurityLevel level) {
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Lsa" };

		return key.SetValue<DWORD>(L"restrictanonymous", 1);
	}

	bool MitigateV1093::MitigationApplies(){
		return true;
	}
}