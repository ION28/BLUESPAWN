#include "hunt/hunts/HuntT1036.h"

#include "util/log/Log.h"
#include "util/filesystem/FileSystem.h"

namespace Hunts {

	HuntT1036::HuntT1036() : Hunt(L"T1036 - Masquerading") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Files;
		dwSourcesInvolved = (DWORD) DataSource::FileSystem;
		dwTacticsUsed = (DWORD) Tactic::DefenseEvasion;
	}

	int HuntT1036::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for " << name << " at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int detections = 0;

		std::vector<FileSystem::Folder> dirs;

		for (auto folder : writableFolders) {
			auto f = FileSystem::Folder(folder);
			if (f.GetFolderExists()) {
				dirs.push_back(f);
				for (auto subdir : f.GetSubdirectories(20)) {
					dirs.push_back(subdir);
				}
			}
		}

		for (auto f : dirs) {
			LOG_VERBOSE(1, L"Scanning " << f.GetFolderPath());
			for (auto value : f.GetFiles(std::nullopt, -1)) {
				if ((std::find(susExts.begin(), susExts.end(), value.GetFileAttribs().extension) != susExts.end())) {
					if (value.GetFileAttribs().extension == L".exe" || value.GetFileAttribs().extension == L".dll") {
						if (!value.GetFileSigned()) {
							reaction.FileIdentified(std::make_shared<FILE_DETECTION>(value));
							detections++;
						}
					} else {
						reaction.FileIdentified(std::make_shared<FILE_DETECTION>(value));
						detections++;
					}
				}
			}
		}

		reaction.EndHunt();
		return detections;
	}

	std::vector<std::shared_ptr<Event>> HuntT1036::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		for (auto folder : writableFolders) {
			auto f = FileSystem::Folder(folder);
			if (f.GetFolderExists()) {
				events.push_back(std::make_shared<FileEvent>(f));
				for (auto subdir : f.GetSubdirectories(20)) {
					events.push_back(std::make_shared<FileEvent>(subdir));
				}
			}
		}

		return events;
	}
}