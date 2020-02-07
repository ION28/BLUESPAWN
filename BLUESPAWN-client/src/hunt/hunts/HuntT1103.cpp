#include "hunt/hunts/HuntT1103.h"
#include "hunt/RegistryHunt.h"
#include "util/log/Log.h"
#include "util/configurations/Registry.h"

using namespace Registry;

namespace Hunts {
	HuntT1103::HuntT1103() : Hunt(L"T1103 - AppInit DLLs") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Processes;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
	}

	int HuntT1103::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for T1103 - AppInit DLLs at level Cursory");
		reaction.BeginHunt(GET_INFO());

		std::map<RegistryKey, std::vector<RegistryValue>> keys;

		auto WinKey = RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" };
		keys.emplace(WinKey, CheckValues(WinKey, {
			{ L"AppInit_Dlls", RegistryType::REG_SZ_T, L"", false, CheckSzEmpty },
			{ L"LoadAppInit_Dlls", RegistryType::REG_DWORD_T, 0, false, CheckDwordEqual },
		}));

		auto WinKeyWow64 = RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows" };
		keys.emplace(WinKeyWow64, CheckValues(WinKeyWow64, {
			{ L"AppInit_Dlls", RegistryType::REG_SZ_T, L"", false, CheckSzEmpty },
			{ L"LoadAppInit_Dlls", RegistryType::REG_DWORD_T, 0, false, CheckDwordEqual },
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