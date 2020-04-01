#include "hunt/hunts/HuntT1037.h"
#include "hunt/RegistryHunt.h"

#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"
#include "util/filesystem/YaraScanner.h"

using namespace Registry;

namespace Hunts{
	HuntT1037::HuntT1037() : Hunt(L"T1037 - Logon Scripts") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory | (DWORD) Aggressiveness::Normal | (DWORD) Aggressiveness::Intensive;
		dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
		dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::LateralMovement;
	}

	int HuntT1037::EvaluateStartupFile(FileSystem::File file, Reaction& reaction, Aggressiveness level) {
		//Scan with YARA at all levels
		LOG_VERBOSE(1, L"Examining " << file.GetFilePath());
		auto& yara = YaraScanner::GetInstance();
		YaraScanResult result = yara.ScanFile(file);
		bool bFileSigned = file.GetFileSigned();

		if(level == Aggressiveness::Cursory || level == Aggressiveness::Normal) {
			if (file.GetFileAttribs().extension == L".exe" && !bFileSigned) {
				reaction.FileIdentified(std::make_shared<FILE_DETECTION>(file.GetFilePath()));
				return 1;
			}
			if(!result && result.vKnownBadRules.size() > 0) {
				reaction.FileIdentified(std::make_shared<FILE_DETECTION>(file.GetFilePath()));
				return 1;
			}
		}
		if(level == Aggressiveness::Normal) {
			if((std::find(sus_exts.begin(), sus_exts.end(), file.GetFileAttribs().extension) != sus_exts.end())) {
				LOG_INFO(L"Startup with suspicious extension identified.");
				reaction.FileIdentified(std::make_shared<FILE_DETECTION>(file.GetFilePath()));
				return 1;
			}
		} else if(level == Aggressiveness::Intensive) {
			reaction.FileIdentified(std::make_shared<FILE_DETECTION>(file.GetFilePath()));
			return 1;
		}

		return 0;
	}

	int Hunts::HuntT1037::AnalyzeRegistryStartupKey(Reaction reaction, Aggressiveness level) {
		std::map<RegistryKey, std::vector<RegistryValue>> keys;

		int detections = 0;
		for(auto& detection : CheckValues(HKEY_CURRENT_USER, L"Environment", {
			    { L"UserInitMprLogonScript", L"", false, CheckSzEmpty }
			}, true, true)){
			reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(detection));
			detections++;

			FileSystem::File file = FileSystem::File(detection.ToString());
			detections += EvaluateStartupFile(file, reaction, level);
        }

		return detections;
	}

	int Hunts::HuntT1037::AnalayzeStartupFolders(Reaction reaction, Aggressiveness level) {
		int detections = 0;

		std::vector<FileSystem::Folder> startup_directories = { FileSystem::Folder(L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp") };
		auto userFolders = FileSystem::Folder(L"C:\\Users").GetSubdirectories(1);
		for (auto userFolder : userFolders) {
			auto folder = FileSystem::Folder(userFolder.GetFolderPath() + L"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp");
			if (folder.GetFolderExists()) {
				startup_directories.emplace_back(folder);
			}
		}
		for (auto folder : startup_directories) {
			LOG_VERBOSE(1, L"Scanning " << folder.GetFolderPath());
			for (auto value : folder.GetFiles(std::nullopt, -1)) {
				detections += EvaluateStartupFile(value, reaction, level);
			}
		}

		return detections;
	}

	int HuntT1037::ScanCursory(const Scope& scope, Reaction reaction) {
		LOG_INFO(L"Hunting for " << name << L" at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int detections = AnalyzeRegistryStartupKey(reaction, Aggressiveness::Cursory);
		detections += AnalayzeStartupFolders(reaction, Aggressiveness::Cursory);

		reaction.EndHunt();
		return detections;
	}

	int HuntT1037::ScanNormal(const Scope& scope, Reaction reaction) {
		LOG_INFO(L"Hunting for " << name << L" at level Normal");
		reaction.BeginHunt(GET_INFO());

		int detections = AnalyzeRegistryStartupKey(reaction, Aggressiveness::Normal);
		detections += AnalayzeStartupFolders(reaction, Aggressiveness::Normal);

		reaction.EndHunt();
		return detections;
	}

	int HuntT1037::ScanIntensive(const Scope& scope, Reaction reaction) {
		LOG_INFO(L"Hunting for " << name << L" at level Intensive");
		reaction.BeginHunt(GET_INFO());

		int detections = AnalyzeRegistryStartupKey(reaction, Aggressiveness::Intensive);
		detections += AnalayzeStartupFolders(reaction, Aggressiveness::Intensive);

		reaction.EndHunt();
		return detections;
	}

	std::vector<std::shared_ptr<Event>> HuntT1037::GetMonitoringEvents() {
		return Registry::GetRegistryEvents(HKEY_CURRENT_USER, L"Environment", true, true, false);
	}
}