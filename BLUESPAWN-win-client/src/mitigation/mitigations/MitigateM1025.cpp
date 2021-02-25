#include "mitigation/mitigations/MitigateM1025.h"
#include "mitigation/policy/ValuePolicy.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

#include <VersionHelpers.h>

using namespace Registry;

namespace Mitigations{
	Mitigation M1025{
		std::wstring(L"M1025 - Privileged Process Integrity"),
		std::wstring(L"Protect processes with high privileges that can be used to interact with critical system components through "
		"use of protected process light, anti-process injection defenses, or other process integrity enforcement "
		"measures."),
		WindowsOS(),
		{
			std::make_unique<RegistryPolicy::ValuePolicy>(
				RegistryKey{ HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Lsa" },
				L"RunAsPPL", 1, RegistryPolicy::ValuePolicy::ValuePolicyType::RequireExact,
				L"Run LSA as PPL", EnforcementLevel::Moderate, L"Run the Local Security Authority as a Protected "
				"Process Lite, preventing process injection and other attacks on lsass.exe's memory", std::nullopt,
				Version{ 6, 3 }
			)
		}
	};
}