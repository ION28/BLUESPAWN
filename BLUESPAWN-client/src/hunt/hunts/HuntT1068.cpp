#include "hunt/hunts/HuntT1068.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"

#include <regex>

using namespace Registry;

namespace Hunts {

	HuntT1068::HuntT1068() : Hunt(L"T1068 - Exploitation for Privilege Escalation") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
		dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
		dwTacticsUsed = (DWORD) Tactic::PrivilegeEscalation;
	}

	int HuntT1068::HuntCVE20201048(Reaction reaction) {
		int detections = 0;

		auto ports = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Ports", true };
		auto printers = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers", true };

		for (auto printer : printers.EnumerateSubkeys()) {
			if (printer.ValueExists(L"Port")) {
				auto filepath = FileSystem::File{ printer.GetValue<std::wstring>(L"Port").value() };

				// Regex ensures the file is an actual drive and not, say, a COM port
				if (std::regex_match(filepath.GetFilePath(), std::wregex(L"([a-zA-z]{1}:\\\\)(.*)")) && filepath.GetFileExists() && filepath.HasReadAccess()) {
					reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ printer, L"Port", printer.GetValue<std::wstring>(L"Port").value() }));
					reaction.FileIdentified(std::make_shared<FILE_DETECTION>(filepath));
					detections += 2;
				}
			}
		}

		for (auto value : ports.EnumerateValues()) {
			auto filepath = FileSystem::File{ value };

			// Regex ensures the file is an actual drive and not, say, a COM port
			if (std::regex_match(filepath.GetFilePath(), std::wregex(L"([a-zA-z]{1}:\\\\)(.*)")) && filepath.GetFileExists() && filepath.HasReadAccess()) {
				reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ ports, value, ports.GetValue<std::wstring>(value).value() }));
				reaction.FileIdentified(std::make_shared<FILE_DETECTION>(filepath));
				detections += 2;
			}
		}

		return detections;
	}

	int HuntT1068::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for " << name << " at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int detections = 0;

		detections += HuntCVE20201048(reaction);

		reaction.EndHunt();
		return detections;
	}

	std::vector<std::shared_ptr<Event>> HuntT1068::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		// CVE-2020-1048
		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers", true, false, true));
		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Ports", true, false, false));

		return events;
	}
}
