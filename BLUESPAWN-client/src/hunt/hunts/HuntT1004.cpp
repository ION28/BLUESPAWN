#include "hunt/hunts/HuntT1004.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"
#include "util/log/HuntLogMessage.h"

using namespace Registry;

namespace Hunts {

	HuntT1004::HuntT1004() : Hunt(L"T1004 - Winlogon Helper DLL") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	int HuntT1004::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for T1004 - Winlogon Helper DLL at level Cursory");
		reaction.BeginHunt(GET_INFO());

		std::map<RegistryKey, std::vector<RegistryValue>> keys;

		auto HKLMWinlogon = RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" };
		keys.emplace(HKLMWinlogon, CheckValues(HKLMWinlogon, {
			{ L"Shell", RegistryType::REG_SZ_T, L"explorer\\.exe,?", true, CheckSzRegexMatch },
			{ L"UserInit", RegistryType::REG_SZ_T, L"C:\\\\(Windows|WINDOWS|windows)\\\\(System32|SYSTEM32|system32)\\\\(U|u)(SERINIT|serinit)\\.(exe|EXE),?", false, CheckSzRegexMatch }
		}));

		auto HKLMWinlogonWoW64 = RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" };
		keys.emplace(HKLMWinlogonWoW64, CheckValues(HKLMWinlogonWoW64, {
			{ L"Shell", RegistryType::REG_SZ_T, L"explorer\\.exe,?", true, CheckSzRegexMatch },
			{ L"UserInit", RegistryType::REG_SZ_T, L"C:\\\\(Windows|WINDOWS|windows)\\\\(System32|SYSTEM32|system32)\\\\(U|u)(SERINIT|serinit)\\.(exe|EXE),?", false, CheckSzRegexMatch }
		}));

		auto HKCUWinlogon = RegistryKey{ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" };
		keys.emplace(HKCUWinlogon, CheckValues(HKCUWinlogon, {
			{ L"Shell", RegistryType::REG_SZ_T, L"", false, CheckSzEmpty },
		}));

		auto HKCUWinlogonWow64 = RegistryKey{ HKEY_CURRENT_USER, L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" };
		keys.emplace(HKCUWinlogonWow64, CheckValues(HKCUWinlogonWow64, {
			{ L"Shell", RegistryType::REG_SZ_T, L"", false, CheckSzEmpty },
		}));

		for(const auto& subkey : CheckSubkeys({ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify" })){
			if(subkey.ValueExists(L"DllName")){
				keys.emplace(subkey, std::vector<RegistryValue>{ { L"DllName", RegistryType::REG_SZ_T, * subkey.GetValue<std::wstring>(L"DllName") }});
			}
		}

		for(const auto& subkey : CheckSubkeys({ HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify" })){
			if(subkey.ValueExists(L"DllName")){
				keys.emplace(subkey, std::vector<RegistryValue>{ { L"DllName", RegistryType::REG_SZ_T, * subkey.GetValue<std::wstring>(L"DllName") }});
			}
		}

		for(const auto& subkey : CheckSubkeys({ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify" })){
			if(subkey.ValueExists(L"DllName")){
				keys.emplace(subkey, std::vector<RegistryValue>{ { L"DllName", RegistryType::REG_SZ_T, * subkey.GetValue<std::wstring>(L"DllName") }});
			}
		}

		for(const auto& subkey : CheckSubkeys({ HKEY_CURRENT_USER, L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify" })){
			if(subkey.ValueExists(L"DllName")){
				keys.emplace(subkey, std::vector<RegistryValue>{ { L"DllName", RegistryType::REG_SZ_T, * subkey.GetValue<std::wstring>(L"DllName") }});
			}
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

}