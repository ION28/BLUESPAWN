#include "hunt/hunts/HuntT1015.h"
#include "hunt/RegistryHunt.h"

#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"
#include "util/filesystem/YaraScanner.h"

#include "common/Utils.h"

using namespace Registry;

namespace Hunts {
	HuntT1015::HuntT1015() : Hunt(L"T1015 - Accessibility Features") {
		dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
		dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
	}

	void HuntT1015::EvaluateRegistry(std::vector<std::shared_ptr<DETECTION>>& detections) {
		for (auto& key : vAccessibilityBinaries) {
			std::vector<RegistryValue> debugger{ CheckValues(HKEY_LOCAL_MACHINE, wsIFEO + key, {
				{ L"Debugger", L"", false, CheckSzEmpty },
            }, true, false) };
			for(auto& detection : debugger){
				REGISTRY_DETECTION(detection);
			}
		}
	}

	void HuntT1015::EvaluateFiles(std::vector<std::shared_ptr<DETECTION>>& detections) {

		auto& yara = YaraScanner::GetInstance();

		for (auto key : vAccessibilityBinaries) {
			FileSystem::File file{ FileSystem::File(L"C:\\Windows\\System32\\" + key) };

			YaraScanResult result = yara.ScanFile(file);

			if (!result && result.vKnownBadRules.size() > 0){
				FILE_DETECTION(file.GetFilePath());
			}
			else if (!file.GetFileSigned()) {
				FILE_DETECTION(file.GetFilePath());
			}
		}
	}

	std::vector<std::shared_ptr<DETECTION>> HuntT1015::RunHunt(const Scope& scope){
		HUNT_INIT();

		EvaluateRegistry(detections);
		EvaluateFiles(detections);

		HUNT_END();
	}

	std::vector<std::shared_ptr<Event>> HuntT1015::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		for (auto key : vAccessibilityBinaries) {
			ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, wsIFEO + key, true, false, false));
		}

		return events;
	}
}
