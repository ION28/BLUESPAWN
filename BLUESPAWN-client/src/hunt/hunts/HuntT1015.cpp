#include "hunt/hunts/HuntT1015.h"
#include "hunt/RegistryHunt.h"

#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"
#include "scan/YaraScanner.h"
#include "user/bluespawn.h"

#include "common/Utils.h"

using namespace Registry;

namespace Hunts {
	HuntT1015::HuntT1015() : Hunt(L"T1015 - Accessibility Features") {
		dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
		dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
	}

	void HuntT1015::EvaluateRegistry(std::vector<std::reference_wrapper<Detection>>& detections) {
		for (auto& key : vAccessibilityBinaries) {
			std::vector<RegistryValue> debugger{ CheckValues(HKEY_LOCAL_MACHINE, wsIFEO + key, {
				{ L"Debugger", L"", false, CheckSzEmpty },
            }, true, false) };
			for(auto& detection : debugger){
				CREATE_DETECTION(Certainty::Certain,
								 RegistryDetectionData{
									 detection.key,
									 detection,
									 RegistryDetectionType::CommandReference,
									 detection.key.GetRawValue(detection.wValueName)
								 }
				);
			}
		}
	}

	void HuntT1015::EvaluateFiles(std::vector<std::reference_wrapper<Detection>>& detections) {

		for (auto name : vAccessibilityBinaries) {
			FileSystem::File file{ FileSystem::File(L"C:\\Windows\\System32\\" + name) };

			if(!file.IsMicrosoftSigned()){
				CREATE_DETECTION(Certainty::Certain, FileDetectionData{ file });
			}
		}
	}

	std::vector<std::reference_wrapper<Detection>> HuntT1015::RunHunt(const Scope& scope){
		HUNT_INIT();

		EvaluateRegistry(detections);
		EvaluateFiles(detections);

		HUNT_END();
	}

	std::vector<std::unique_ptr<Event>> HuntT1015::GetMonitoringEvents() {
		std::vector<std::unique_ptr<Event>> events;

		for (auto key : vAccessibilityBinaries) {
			Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE, wsIFEO + key, true, false, false);
		}

		return events;
	}
}
