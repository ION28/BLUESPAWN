#include "hunt/hunts/HuntT1060.h"
#include "hunt/RegistryHunt.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"

using namespace Registry;

namespace Hunts {
	HuntT1060::HuntT1060() : Hunt(L"T1060 - Registry Run Keys / Startup Folder") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;

		auto HKLMRun = RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run" };
		auto HKCURun = RegistryKey{ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run" };
		auto HKLMRunOnce = RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" };
		auto HKCURunOnce = RegistryKey{ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" };
		auto HKLMRunOnceEx = RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx" };
		auto HKCURunOnceEx = RegistryKey{ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx" };
		auto HKLMRunWow64 = RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" };
		auto HKCURunWow64 = RegistryKey{ HKEY_CURRENT_USER, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" };
		auto HKLMRunOnceWow64 = RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce" };
		auto HKCURunOnceWow64 = RegistryKey{ HKEY_CURRENT_USER, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce" };
		auto HKLMRunOnceExWow64 = RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx" };
		auto HKCURunOnceExWow64 = RegistryKey{ HKEY_CURRENT_USER, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx" };
		auto HKLMExplorerRun = RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" };
		auto HKCUExplorerRun = RegistryKey{ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" };
		auto HKLMExplorerRunWow64 = RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" };
		auto HKCUExplorerRunWow64 = RegistryKey{ HKEY_CURRENT_USER, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" };

		RunKeys = {
			HKLMRun, HKLMRunOnce, HKLMRunOnceEx,
			HKCURun, HKCURunOnce, HKCURunOnceEx,
			HKLMRunWow64, HKLMRunOnceWow64, HKLMRunOnceExWow64,
			HKCURunWow64, HKCURunOnceWow64, HKCURunOnceExWow64,
			HKLMExplorerRun, HKCUExplorerRun,
			HKLMExplorerRunWow64, HKCUExplorerRunWow64,
		};

		auto HKLMCMDRun = RegistryKey{ HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Command Processor" };
		auto HKLMCMDRunWow64 = RegistryKey{ HKEY_CURRENT_USER, L"SOFTWARE\\WOW6432Node\\Microsoft\\Command Processor" };
		auto HKCUCMDRun = RegistryKey{ HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Command Processor" };
		auto HKCUCMDRunWow64 = RegistryKey{ HKEY_CURRENT_USER, L"SOFTWARE\\WOW6432Node\\Microsoft\\Command Processor" };

		CMDKeys = {
			HKLMCMDRun, HKLMCMDRunWow64, HKCUCMDRun, HKCUCMDRunWow64,
		};

		auto HKCUUShell = RegistryKey{ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" };
		auto HKLMUShell = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" };
		auto HKCUShell = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" };
		auto HKLMShell = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" };
		auto HKCUUShellWow64 = RegistryKey{ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" };
		auto HKLMUShellWow64 = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" };
		auto HKCUShellWow64 = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" };
		auto HKLMShellWow64 = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" };

		ShellKeys = {
			HKLMUShell, HKLMShell,  HKLMShellWow64, HKLMUShellWow64,
		};

		UserShellKeys = {
			HKCUShell, HKCUUShell, HKCUShellWow64, HKCUUShellWow64,
		};
	}

	int HuntT1060::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO(L"Hunting for " << name << L" at level Cursory");
		reaction.BeginHunt(GET_INFO());

		std::map<RegistryKey, std::vector<RegistryValue>> keys;
		
		for(auto key : RunKeys){
			keys.emplace(key, CheckKeyValues(key));
		}

		for(auto key : CMDKeys) {
			keys.emplace(key, CheckValues(key, {
				{ L"AutoRun", RegistryType::REG_SZ_T, L"", false, CheckSzEmpty }
			}));
		}

		for (auto key : UserShellKeys) {
			keys.emplace(key, CheckValues(key, {
				{ L"Startup", RegistryType::REG_EXPAND_SZ_T, L"%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", false, CheckSzEqual }
			}));
		}

		for (auto key : ShellKeys) {
			keys.emplace(key, CheckValues(key, {
				{ L"Common Startup", RegistryType::REG_EXPAND_SZ_T, L"%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", false, CheckSzEqual }
			}));
		}

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

	std::vector<std::shared_ptr<Event>> HuntT1060::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;
		for (auto key : RunKeys) { events.push_back(std::make_shared<RegistryEvent>(key)); }
		for (auto key : CMDKeys) { events.push_back(std::make_shared<RegistryEvent>(key)); }
		for (auto key : ShellKeys) { events.push_back(std::make_shared<RegistryEvent>(key)); }
		for (auto key : UserShellKeys) { events.push_back(std::make_shared<RegistryEvent>(key)); }
		return events;
	}
}