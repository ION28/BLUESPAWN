#include "hunt/hunts/HuntT1060.h"
#include "hunt/RegistryHunt.h"

#include "util/log/Log.h"
#include "util/configurations/Registry.h"

using namespace Registry;

namespace Hunts {
	HuntT1060::HuntT1060(HuntRegister& record) : Hunt(record, L"T1060 - Registry Run Keys / Startup Folder") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	int HuntT1060::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for T1060 - Registry Run Keys / Startup Folder at level Cursory");
		reaction.BeginHunt(GET_INFO());

		std::map<RegistryKey, std::vector<RegistryValue>> keys;

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

		std::vector<RegistryKey> RunKeys = {
			HKLMRun, HKLMRunOnce, HKLMRunOnceEx,
			HKCURun, HKCURunOnce, HKCURunOnceEx,
			HKLMRunWow64, HKLMRunOnceWow64, HKLMRunOnceExWow64,
			HKCURunWow64, HKCURunOnceWow64, HKCURunOnceExWow64,
			HKLMExplorerRun, HKCUExplorerRun,
		};
		
		for(auto key : RunKeys){
			keys.emplace(key, CheckKeyValues(key));
		}

		auto HKCUShell = RegistryKey{ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" };
		keys.emplace(HKCUShell, CheckValues(HKCUShell, {
		    { L"Startup", RegistryType::REG_EXPAND_SZ_T, L"%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", false, CheckSzEqual }
		}));

		auto HKLMUShell = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" };
		keys.emplace(HKLMUShell, CheckValues(HKLMUShell, {
			{ L"Common Startup", RegistryType::REG_EXPAND_SZ_T, L"%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", false, CheckSzEqual }
		}));


		auto HKLMShell = RegistryKey{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" };
		keys.emplace(HKLMShell, CheckValues(HKLMShell, {
			{ L"Common Startup", RegistryType::REG_EXPAND_SZ_T, L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", false, CheckSzEqual }
		}));

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
}