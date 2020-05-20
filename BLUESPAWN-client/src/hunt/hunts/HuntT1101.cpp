#include "hunt/hunts/HuntT1101.h"
#include "hunt/RegistryHunt.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"
#include "util/filesystem/YaraScanner.h"

using namespace Registry;

namespace Hunts {
	HuntT1101::HuntT1101() : Hunt(L"T1101 - Security Support Provider") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	int HuntT1101::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO(L"Hunting for " << name << " at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int detections = 0;

		auto lsa = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa" };
		auto lsa2 = RegistryKey(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig");

		for (auto key : { lsa, lsa2 }) {
			auto Packages = key.GetValue<std::vector<std::wstring>>(L"Security Packages");
			if (Packages) {
				for (auto Package : Packages.value()) {
					if (Package != L"\"\"") {
						auto filepath = FileSystem::SearchPathExecutable(Package + L".dll");

						if (filepath) {
							FileSystem::File file = FileSystem::File(filepath.value());
							if (file.GetFileExists() && !file.GetFileSigned()) {
								reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ key, L"Security Packages", key.GetValue<std::vector<std::wstring>>(L"Security Packages").value() }));
								reaction.FileIdentified(std::make_shared<FILE_DETECTION>(file));
								detections += 2;
							}
						}
					}
				}
			}
		}

		reaction.EndHunt();
		return detections;
	}

	std::vector<std::shared_ptr<Event>> HuntT1101::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", false, false, true));

		return events;
	}
}