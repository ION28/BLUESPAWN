#include "hunt/hunts/HuntT1138.h"
#include "hunt/RegistryHunt.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"

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

		std::map<RegistryKey, std::vector<RegistryValue>> keys;

		auto SDB = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB" };
		keys.emplace(SDB, CheckKeyValues(SDB));

		auto Custom = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom" };
		keys.emplace(Custom, CheckKeyValues(Custom));

		auto SDBWow64 = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB" };
		keys.emplace(SDBWow64, CheckKeyValues(SDBWow64));

		auto CustomWow64 = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom" };
		keys.emplace(CustomWow64, CheckKeyValues(CustomWow64));

		int detections = 0;
		for(const auto& key : keys){
			for(const auto& value : key.second){
				reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(key.first.GetName(), value));
				detections++;
			}
		}

		reaction.EndHunt();
		return detections;
	}

	std::vector<std::shared_ptr<Event>> HuntT1138::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;
		events.push_back(std::make_shared<RegistryEvent>(RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB" }));
		events.push_back(std::make_shared<RegistryEvent>(RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom" }));
		events.push_back(std::make_shared<RegistryEvent>(RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB" }));
		events.push_back(std::make_shared<RegistryEvent>(RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom" }));
		return events;
	}
}