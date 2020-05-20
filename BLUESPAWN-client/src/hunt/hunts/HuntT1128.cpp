#include "hunt/hunts/HuntT1128.h"
#include "hunt/RegistryHunt.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"
#include "util/filesystem/YaraScanner.h"
#include "util/processes/ProcessUtils.h"

using namespace Registry;

namespace Hunts {

	HuntT1128::HuntT1128() : Hunt(L"T1128 - Netsh Helper DLL") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
		dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	int HuntT1128::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for " << name << " at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int detections = 0;

		auto netshKey = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Netsh", true };

		for (auto& helperDllValue : CheckKeyValues(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Netsh", true, false)) {
			auto filepath = FileSystem::SearchPathExecutable(std::get<std::wstring>(helperDllValue.data));
			if (filepath) {
				FileSystem::File helperDll{ *filepath };
				if (!helperDll.GetFileSigned()) {
					reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(helperDllValue));

						auto& yara = YaraScanner::GetInstance();
						YaraScanResult result = yara.ScanFile(helperDll);

						reaction.FileIdentified(std::make_shared<FILE_DETECTION>(helperDll));

						detections += 2;
					}
				}
			}
		}

		reaction.EndHunt();
		return detections;
	}

	std::vector<std::shared_ptr<Event>> HuntT1128::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Netsh", true, false, false));

		return events;
	}
}