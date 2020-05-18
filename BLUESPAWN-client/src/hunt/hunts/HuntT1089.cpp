#include "hunt/hunts/HuntT1089.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"

using namespace Registry;

namespace Hunts {

	HuntT1089::HuntT1089() : Hunt(L"T1089 - Disabling Security Tools") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Network;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::DefenseEvasion;
	}

	int HuntT1089::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for " << name << " at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int detections = 0;

		auto DomainProfile = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile" };
		auto StandardProfile = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile" };
		auto PublicProfile = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile" };

		for (auto key : { DomainProfile, StandardProfile, PublicProfile }) {
			auto allowedapps = RegistryKey{ key, L"AuthorizedApplications\\List" };
			if (allowedapps.Exists()) {
				for (auto ProgramException : allowedapps.EnumerateValues()) {
					reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ allowedapps, ProgramException, allowedapps.GetValue<std::wstring>(ProgramException).value() }));
					auto program = FileSystem::File{ ProgramException };
					if (!program.GetFileSigned()) {
						reaction.FileIdentified(std::make_shared<FILE_DETECTION>(program));
					}
				}
			}

			auto ports = RegistryKey{ key, L"GloballyOpenPorts\\List" };
			if (ports.Exists()) {
				for (auto PortsException : ports.EnumerateValues()) {
					reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ ports, PortsException, ports.GetValue<std::wstring>(PortsException).value() }));
				}
			}
		}

		reaction.EndHunt();
		return detections;
	}

	std::vector<std::shared_ptr<Event>> HuntT1089::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile", false, false, true));
		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile", false, false, true));
		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile", false, false, true));

		return events;
	}
}