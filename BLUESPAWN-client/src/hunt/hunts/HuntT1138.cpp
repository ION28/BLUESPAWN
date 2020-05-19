#include "hunt/hunts/HuntT1138.h"
#include "hunt/RegistryHunt.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"

#include "common/Utils.h"

using namespace Registry;

namespace Hunts {
	HuntT1138::HuntT1138() : Hunt(L"T1138 - Application Shimming") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
	}

	int HuntT1138::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO(L"Hunting for " << name << L" at level Cursory");
		reaction.BeginHunt(GET_INFO());

		auto& detections = CheckKeyValues(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB", true, false);
		ADD_ALL_VECTOR(detections, CheckKeyValues(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom", true, false));

		int detectionCount = 0;
		for(const auto& detection : detections){
			reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(detection));
			detectionCount++;
		}

		reaction.EndHunt();
		return detectionCount;
	}

	std::vector<std::shared_ptr<Event>> HuntT1138::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;

		ADD_ALL_VECTOR(events, GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB"));
		ADD_ALL_VECTOR(events, GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom"));
		events.push_back(std::make_shared<FileEvent>(FileSystem::Folder{ L"C:\\Windows\\AppPatch\\Custom" }));
		events.push_back(std::make_shared<FileEvent>(FileSystem::Folder{ L"C:\\Windows\\AppPatch\\Custom\\Custom64" }));

		return events;
	}
}