#include "hunt/hunts/HuntT1484.h"

#include "util/log/Log.h"
#include "util/filesystem/FileSystem.h"

namespace Hunts {

	HuntT1484::HuntT1484() : Hunt(L"T1484 - Group Policy Modification") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD)Category::Files;
		dwSourcesInvolved = (DWORD)DataSource::FileSystem | (DWORD)DataSource::GPO;
		dwTacticsUsed = (DWORD) Tactic::DefenseEvasion;
	}

	int HuntT1484::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for " << name << " at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int detections = 0;

		auto userFolders = FileSystem::Folder(L"C:\\Users").GetSubdirectories(1);
		for (auto userFolder : userFolders) {
			auto ntuserman = FileSystem::File(userFolder.GetFolderPath() + L"\\ntuser.man");
			if (ntuserman.GetFileExists()) {
				detections++;
				reaction.FileIdentified(std::make_shared<FILE_DETECTION>(ntuserman));
			}
		}
		reaction.EndHunt();
		return detections;
	}

	std::vector<std::shared_ptr<Event>> HuntT1484::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		auto userFolders = FileSystem::Folder(L"C:\\Users").GetSubdirectories(1);
		for (auto userFolder : userFolders) {
			events.push_back(std::make_shared<FileEvent>(userFolder));
		}

		return events;
	}
}