#include "mitigation/mitigations/MitigateM1047.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"
#include "util/eventlogs/EventLogs.h"

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
		) {
	
		channelList.push_back(L"Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational");
		channelList.push_back(L"Microsoft-Windows-Bits-Client/Operational");
		channelList.push_back(L"Microsoft-Windows-AppLocker/EXE and DLL");
		channelList.push_back(L"Microsoft-Windows-AppLocker/MSI and Script");
		channelList.push_back(L"Security");
		channelList.push_back(L"System");
		channelList.push_back(L"Microsoft-Windows-Powershell/Operational");
		channelList.push_back(L"Microsoft-Windows-TaskScheduler/Operational");
		channelList.push_back(L"Microsoft-Windows-Windows Defender/Operational");
		channelList.push_back(L"Microsoft-Windows-Windows Defender/Operational");
		channelList.push_back(L"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall");
		channelList.push_back(L"Microsoft-Windows-Sysmon/Operational");
	}

	bool MitigateM1047::MitigationIsEnforced(SecurityLevel level) {
		bool enforced = true;

		// Check if Sysmon service is installed is is not disabled or manual
		auto sysmon64 = Registry::RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Sysmon64" };
		auto sysmon = Registry::RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Sysmon" };

		if (!sysmon.Exists() && !sysmon64.Exists()) {
			LOG_VERBOSE(1, L"Sysmon is not installed.");
			enforced = false;
		}
		if (sysmon.Exists() && *sysmon.GetValue<DWORD>(L"Start") >= 3UL || 
			sysmon64.Exists() && *sysmon64.GetValue<DWORD>(L"Start") >= 3UL) {

			LOG_VERBOSE(1, L"Sysmon is set to manual or disabled.");
			enforced = false;
		}

		// Check if EventLog service is enabled and not manual
		auto eventLogService = Registry::RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\EventLog" };
		if (!eventLogService.Exists()) {
			LOG_VERBOSE(1, L"Windows Event Log Service is not installed.");
			enforced = false;
		}
		else if (eventLogService.GetValue<DWORD>(L"Start") >= 3u) {
			LOG_VERBOSE(1, L"Windows Event Log Service is set to manual or disabled.");
			enforced = false;
		}

		for (std::wstring channel : channelList) {
			if (!EventLogs::IsChannelOpen(channel)) {
				LOG_VERBOSE(1, channel + L" is disabled.");
				enforced = false;
			}
		}

		return enforced;
	}

	bool MitigateM1047::EnforceMitigation(SecurityLevel level) {
		bool enforced = true;

		// Ensure Sysmon service is installed is is not disabled or manual
		auto sysmon64 = Registry::RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Sysmon64" };
		auto sysmon = Registry::RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Sysmon" };

		if (!sysmon.Exists() && !sysmon64.Exists()) {
			LOG_VERBOSE(1, L"Sysmon is not installed.");
			enforced = false;
		}
		if (sysmon.Exists() && *sysmon.GetValue<DWORD>(L"Start") >= 3UL) {
			LOG_VERBOSE(1, L"Attempting to set SYSTEM\\CurrentControlSet\\Services\\Sysmon\\Start to 2.");
			enforced &= sysmon.SetValue<DWORD>(L"Start", 2);
		}
		if (sysmon64.Exists() && *sysmon64.GetValue<DWORD>(L"Start") >= 3UL) {
			LOG_VERBOSE(1, L"Attempting to set SYSTEM\\CurrentControlSet\\Services\\Sysmon64\\Start to 2.");
			enforced &= sysmon64.SetValue<DWORD>(L"Start", 2);
		}

		// Check if EventLog service is enabled and not manual
		auto eventLogService = Registry::RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\EventLog" };
		if (!eventLogService.Exists()) {
			LOG_VERBOSE(1, L"Windows Event Log Service is not installed.");
			enforced = false;
		}
		else if (*eventLogService.GetValue<DWORD>(L"Start") >= 3UL) {
			LOG_VERBOSE(1, L"Attempting to set SYSTEM\\CurrentControlSet\\Services\\EventLog\\Start to 2.");
			enforced &= eventLogService.SetValue<DWORD>(L"Start", 2);
		}

		for (std::wstring channel : channelList) {
			if (!EventLogs::IsChannelOpen(channel)) {
				LOG_VERBOSE(1, L"Attempting to open event log channel " + channel + L".");
				bool result = EventLogs::OpenChannel(channel);
				if (!result) {
					LOG_VERBOSE(1, L"Failed to open event log channel " + channel + L".");
					enforced &= result;
				}
			}
		}

		return enforced;
	}

	bool MitigateM1047::MitigationApplies() {
		return true;
	}
}
