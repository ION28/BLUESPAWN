#include "mitigation/mitigations/MitigateM1028-WFW.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"

using namespace Registry;

namespace Mitigations {

	MitigateM1028WFW::MitigateM1028WFW() :
		Mitigation(
			L"M1028-WFW - Windows Firewall must be enabled with no exceptions",
			L"The Windows Firewall is an important host-based security control that"
			" should not be disabled. Furthermore, it should not permit exceptions. "
			"Instead, users should create proper rules for specific programs.",
			L"wfw",
			SoftwareAffected::OperatingSystem,
			MitigationSeverity::High
		) {}

	bool MitigateM1028WFW::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO(1, "Checking for presence of " << name);

		auto DomainProfile = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile" };
		auto StandardProfile = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile" };
		auto PublicProfile = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile" };

		for (auto key : { DomainProfile, StandardProfile, PublicProfile }) {
			// V-17417
			if (!key.ValueExists(L"EnableFirewall") || key.GetValue<DWORD>(L"EnableFirewall") != 1) {
				LOG_VERBOSE(1, L"Value for EnableFirewall is not set to 1 for " << key.ToString());
				return false;
			}
			if (!key.ValueExists(L"DisableNotifications") || key.GetValue<DWORD>(L"DisableNotifications") != 0) {
				LOG_VERBOSE(1, L"Value for DisableNotifications is not set to 0 for " << key.ToString());
				return false;
			}
			// V-17418
			if (!key.ValueExists(L"DefaultInboundAction") || key.GetValue<DWORD>(L"DefaultInboundAction") != 1) {
				LOG_VERBOSE(1, L"Value for DefaultInboundAction is not set to 1 for " << key.ToString());
				return false;
			}
		}

		LOG_VERBOSE(1, L"Mitigation " << name << L" is enforced.");
		return true;
	}

	bool MitigateM1028WFW::EnforceMitigation(SecurityLevel level) {
		auto DomainProfile = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile" };
		auto StandardProfile = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile" };
		auto PublicProfile = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile" };

		for (auto key : { DomainProfile, StandardProfile, PublicProfile }) {
			LOG_VERBOSE(1, L"Attempting to set EnableFirewall to 1 for " << key.ToString());
			if (!key.SetValue<DWORD>(L"EnableFirewall", 1)) {
				return false;
			}

			LOG_VERBOSE(1, L"Attempting to set DisableNotifications to 0 for " << key.ToString());
			if (!key.SetValue<DWORD>(L"DisableNotifications", 0)) {
				return false;
			}

			LOG_VERBOSE(1, L"Attempting to set DefaultInboundAction to 1 for " << key.ToString());
			if (!key.SetValue<DWORD>(L"DefaultInboundAction", 1)) {
				return false;
			}
		}

		return true;
	}

	bool MitigateM1028WFW::MitigationApplies(){
		return true;
	}
}
