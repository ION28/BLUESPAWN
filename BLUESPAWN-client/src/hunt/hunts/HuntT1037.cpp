#include "hunt/hunts/HuntT1037.h"
#include "hunt/RegistryHunt.h"

#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"
#include "util/filesystem/YaraScanner.h"

using namespace Registry;

namespace Hunts{
	HuntT1037::HuntT1037() : Hunt(L"T1037 - Logon Scripts") {
		dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
		dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::LateralMovement;
	}


	std::vector<std::shared_ptr<DETECTION>> HuntT1037::RunHunt(const Scope& scope) {
		HUNT_INIT();

		for(auto& detection : CheckValues(HKEY_CURRENT_USER, L"Environment", {
				{ L"UserInitMprLogonScript", L"", false, CheckSzEmpty }
		}, true, true)){
			REGISTRY_DETECTION(detection);
		}

		std::vector<FileSystem::Folder> startup_directories = { FileSystem::Folder(L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp") };
		auto userFolders = FileSystem::Folder(L"C:\\Users").GetSubdirectories(1);
		for(auto userFolder : userFolders) {
			auto folder = FileSystem::Folder(userFolder.GetFolderPath() + L"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp");
			if(folder.GetFolderExists()) {
				startup_directories.emplace_back(folder);
			}
		}
		for(auto folder : startup_directories) {
			LOG_VERBOSE(1, L"Scanning " << folder.GetFolderPath());
			for(auto value : folder.GetFiles(std::nullopt, -1)) {
				FILE_DETECTION(value.GetFilePath());
			}
		}

		HUNT_END();
	}

	std::vector<std::shared_ptr<Event>> HuntT1037::GetMonitoringEvents() {
		return Registry::GetRegistryEvents(HKEY_CURRENT_USER, L"Environment", true, true, false);
	}
}