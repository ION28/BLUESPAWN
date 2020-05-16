#include "hunt/hunts/HuntT1013.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"
#include "util/filesystem/YaraScanner.h"

using namespace Registry;

namespace Hunts {

	HuntT1013::HuntT1013() : Hunt(L"T1013 - Port Monitors") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
		dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
	}

	int HuntT1013::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for " << name << " at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int detections = 0;

		auto monitors = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors" };

		for (auto monitor : monitors.EnumerateSubkeys()) {
			if (monitor.ValueExists(L"Driver")) {
				auto filepath = FileSystem::SearchPathExecutable(monitor.GetValue<std::wstring>(L"Driver").value());

				if (filepath && FileSystem::CheckFileExists(*filepath)) {
					FileSystem::File monitordll = FileSystem::File(*filepath);

					if (!monitordll.GetFileSigned()) {
						reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ monitor, L"Driver", monitor.GetValue<std::wstring>(L"Driver").value() }));

						auto& yara = YaraScanner::GetInstance();
						YaraScanResult result = yara.ScanFile(monitordll);

						reaction.FileIdentified(std::make_shared<FILE_DETECTION>(monitordll));

						detections += 2;
					}
				}
			}
		}

		reaction.EndHunt();
		return detections;
	}

	std::vector<std::shared_ptr<Event>> HuntT1013::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors", false, false, true));

		return events;
	}
}