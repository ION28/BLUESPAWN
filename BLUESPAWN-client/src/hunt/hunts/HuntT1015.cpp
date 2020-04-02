#include "hunt/hunts/HuntT1015.h"
#include "hunt/RegistryHunt.h"

#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"
#include "util/filesystem/YaraScanner.h"

#include "common/Utils.h"

using namespace Registry;

namespace Hunts {
	HuntT1015::HuntT1015() : Hunt(L"T1015 - Accessibility Features") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory | (DWORD) Aggressiveness::Normal;
		dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
		dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
	}

	int HuntT1015::EvaluateRegistry(Reaction& reaction) {
		int detections = 0;

		auto& yara = YaraScanner::GetInstance();

		for (auto key : vAccessibilityBinaries) {
			std::vector<RegistryValue> debugger{ CheckValues(HKEY_LOCAL_MACHINE, wsIFEO + key, {
				{ L"Debugger", L"", false, CheckSzEmpty },
            }, true, false) };
			for(auto& detection : debugger){
				detections++;
				reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(detection));
				LOG_INFO(detection.key.GetName() << L" is configured with a Debugger value of " << detection);

				FileSystem::File file = FileSystem::File(detection.ToString());
				YaraScanResult result = yara.ScanFile(file);
				bool bFileSigned = file.GetFileSigned();

				if(!bFileSigned || (!result && result.vKnownBadRules.size() > 0)) {
					detections++;
					reaction.FileIdentified(std::make_shared<FILE_DETECTION>(file.GetFilePath()));
				}
			}
		}

		return detections;
	}

	int HuntT1015::EvaluateFiles(Reaction& reaction, bool bScanYara) {
		int detections = 0;

		for (auto key : vAccessibilityBinaries) {
			FileSystem::File file = FileSystem::File(L"C:\\Windows\\System32\\" + key);

			if (!file.GetFileSigned()) {
				if (bScanYara) { 
					auto& yara = YaraScanner::GetInstance();
					YaraScanResult result = yara.ScanFile(file);
				}

				LOG_INFO(file.GetFilePath() << L" is not signed!");
				reaction.FileIdentified(std::make_shared<FILE_DETECTION>(file.GetFilePath()));
				detections++;
			}
		}

		return detections;
	}

	int HuntT1015::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO(L"Hunting for " << name  << L" at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int results = EvaluateRegistry(reaction);
		results += EvaluateFiles(reaction, false);

		reaction.EndHunt();
		return results;
	}

	int HuntT1015::ScanNormal(const Scope& scope, Reaction reaction) {
		LOG_INFO(L"Hunting for " << name << L" at level Normal");
		reaction.BeginHunt(GET_INFO());


		int results = EvaluateRegistry(reaction);
		results += EvaluateFiles(reaction, true);
		
		reaction.EndHunt();
		return results;
	}

	std::vector<std::shared_ptr<Event>> HuntT1015::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		for (auto key : vAccessibilityBinaries) {
			ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, wsIFEO + key, true, false, false));
		}

		return events;
	}
}
