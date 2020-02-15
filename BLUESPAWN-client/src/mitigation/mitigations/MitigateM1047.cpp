#include "mitigation/mitigations/MitigateM1047.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"
#include "hunt/reaction/Log.h"

namespace Mitigations {

	MitigateM1047::MitigateM1047() :
		Mitigation(
			L"M1047 - Audit",
			L"checks the registry to ensure that key but optional \
			event log channels are enabled. These sources are used by many Hunts \
			and monitoring services in BLUESPAWN.",
			L"evt",
			SoftwareAffected::InternalService,
			MitigationSeverity::Medium
		) {}

	bool MitigateM1047::MitigationIsEnforced(SecurityLevel level) {
		bool enforced = true;

		// Check if Sysmon is installed
		auto sysmon64 = Registry::RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Sysmon64" };
		auto sysmon = Registry::RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Sysmon" };

		if (!sysmon.Exists() && !sysmon64.Exists()) {
			LOG_VERBOSE(1, L"Sysmon is not installed.");
			enforced = false;
		}

		// Ensure Sysmon is not disabled or manual
		if (sysmon.Exists() && sysmon.GetValue<DWORD>(L"Start") >= 3 || sysmon64.Exists() && sysmon64.GetValue<DWORD>(L"Start") >= 3) {
			LOG_VERBOSE(1, L"Sysmon is set to manual or disabled.");
			enforced = false;
		}

		// Check if EventLogs are enabled
		auto eventLogService = Registry::RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\EventLog" };
		if (!eventLogService.Exists()) {
			LOG_VERBOSE(1, L"Windows Event Log Service is not installed.");
			enforced = false;
		}
		else if (eventLogService.GetValue<DWORD>(L"Start") >= 3) {
			LOG_VERBOSE(1, L"Windows Event Log Service is set to manual or disabled.");
			enforced = false;
		}

		return enforced;
	}

	bool MitigateM1047::EnforceMitigation(SecurityLevel level) {
		return true;
	}

	bool MitigateM1047::MitigationApplies() {
		return true;
	}
}