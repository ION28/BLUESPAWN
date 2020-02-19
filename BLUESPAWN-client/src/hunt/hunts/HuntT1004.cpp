#include "hunt/hunts/HuntT1004.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"
#include "util/log/HuntLogMessage.h"
#include "util/eventlogs/EventLogs.h"

using namespace Registry;

namespace Hunts {

	HuntT1004::HuntT1004() : Hunt(L"T1004 - Winlogon Helper DLL") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	int HuntT1004::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for " << name << " at level Cursory");
		reaction.BeginHunt(GET_INFO());

		std::map<RegistryKey, std::vector<RegistryValue>> keys;

		auto HKLMWinlogon = RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" };
		keys.emplace(HKLMWinlogon, CheckValues(HKLMWinlogon, {
			{ L"Shell", RegistryType::REG_SZ_T, L"explorer\\.exe,?", true, CheckSzRegexMatch },
			{ L"UserInit", RegistryType::REG_SZ_T, L"(C:\\\\(Windows|WINDOWS|windows)\\\\(System32|SYSTEM32|system32)\\\\)?(U|u)(SERINIT|serinit)\\.(exe|EXE),?", false, CheckSzRegexMatch }
		}));

		auto HKLMWinlogonWoW64 = RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" };
		keys.emplace(HKLMWinlogonWoW64, CheckValues(HKLMWinlogonWoW64, {
			{ L"Shell", RegistryType::REG_SZ_T, L"explorer\\.exe,?", true, CheckSzRegexMatch },
			{ L"UserInit", RegistryType::REG_SZ_T, L"(C:\\\\(Windows|WINDOWS|windows)\\\\(System32|SYSTEM32|system32)\\\\)?(U|u)(SERINIT|serinit)\\.(exe|EXE),?", false, CheckSzRegexMatch }
		}));

		auto HKCUWinlogon = RegistryKey{ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" };
		keys.emplace(HKCUWinlogon, CheckValues(HKCUWinlogon, {
			{ L"Shell", RegistryType::REG_SZ_T, L"explorer\\.exe,?", false, CheckSzRegexMatch },
			{ L"UserInit", RegistryType::REG_SZ_T, L"(C:\\\\(Windows|WINDOWS|windows)\\\\(System32|SYSTEM32|system32)\\\\)?(U|u)(SERINIT|serinit)\\.(exe|EXE),?", false, CheckSzRegexMatch }
		}));

		auto HKCUWinlogonWow64 = RegistryKey{ HKEY_CURRENT_USER, L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" };
		keys.emplace(HKCUWinlogonWow64, CheckValues(HKCUWinlogonWow64, {
			{ L"Shell", RegistryType::REG_SZ_T, L"explorer\\.exe,?", false, CheckSzRegexMatch },
			{ L"UserInit", RegistryType::REG_SZ_T, L"(C:\\\\(Windows|WINDOWS|windows)\\\\(System32|SYSTEM32|system32)\\\\)?(U|u)(SERINIT|serinit)\\.(exe|EXE),?", false, CheckSzRegexMatch }
		}));

		auto HKLMNotify = RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify" };
		auto HKLMNotifyWow64 = RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify" };
		auto HKCUNotify = RegistryKey{ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify" };
		auto HKCUNotifyWow64 = RegistryKey{ HKEY_CURRENT_USER, L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify" };

		for (auto value : HKLMNotify.EnumerateValues()) {
			RegistryValue reg = { value, RegistryType::REG_SZ_T, *HKLMNotify.GetValue<std::wstring>(value) };
			keys.emplace(HKLMNotify, std::vector<RegistryValue>{ reg });
		}

		for (auto value : HKLMNotifyWow64.EnumerateValues()) {
			RegistryValue reg = { value, RegistryType::REG_SZ_T, *HKLMNotifyWow64.GetValue<std::wstring>(value) };
			keys.emplace(HKLMNotifyWow64, std::vector<RegistryValue>{ reg });
		}

		for (auto value : HKCUNotify.EnumerateValues()) {
			RegistryValue reg = { value, RegistryType::REG_SZ_T, *HKCUNotify.GetValue<std::wstring>(value) };
			keys.emplace(HKCUNotify, std::vector<RegistryValue>{ reg });
		}

		for (auto value : HKCUNotifyWow64.EnumerateValues()) {
			RegistryValue reg = { value, RegistryType::REG_SZ_T, *HKCUNotifyWow64.GetValue<std::wstring>(value) };
			keys.emplace(HKCUNotifyWow64, std::vector<RegistryValue>{ reg });
		}

		for (auto subkey : HKLMNotify.EnumerateSubkeys()) {
			for (auto value : subkey.EnumerateValues()) {
				RegistryValue reg = { value, RegistryType::REG_SZ_T, *subkey.GetValue<std::wstring>(value) };
				keys.emplace(subkey, std::vector<RegistryValue>{ reg });
			}
		}

		for (auto subkey : HKLMNotifyWow64.EnumerateSubkeys()) {
			for (auto value : subkey.EnumerateValues()) {
				RegistryValue reg = { value, RegistryType::REG_SZ_T, *subkey.GetValue<std::wstring>(value) };
				keys.emplace(subkey, std::vector<RegistryValue>{ reg });
			}
		}

		for (auto subkey : HKCUNotify.EnumerateSubkeys()) {
			for (auto value : subkey.EnumerateValues()) {
				RegistryValue reg = { value, RegistryType::REG_SZ_T, *subkey.GetValue<std::wstring>(value) };
				keys.emplace(subkey, std::vector<RegistryValue>{ reg });
			}
		}

		for (auto subkey : HKCUNotifyWow64.EnumerateSubkeys()) {
			for (auto value : subkey.EnumerateValues()) {
				RegistryValue reg = { value, RegistryType::REG_SZ_T, *subkey.GetValue<std::wstring>(value) };
				keys.emplace(subkey, std::vector<RegistryValue>{ reg });
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

	std::vector<std::shared_ptr<Event>> HuntT1004::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;
		events.push_back(std::make_shared<RegistryEvent>(RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" }));
		events.push_back(std::make_shared<RegistryEvent>(RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" }));
		events.push_back(std::make_shared<RegistryEvent>(RegistryKey{ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" }));
		events.push_back(std::make_shared<RegistryEvent>(RegistryKey{ HKEY_CURRENT_USER, L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" }));
		events.push_back(std::make_shared<RegistryEvent>(RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify" }));
		events.push_back(std::make_shared<RegistryEvent>(RegistryKey{ HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify" }));
		events.push_back(std::make_shared<RegistryEvent>(RegistryKey{ HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify" }));
		events.push_back(std::make_shared<RegistryEvent>(RegistryKey{ HKEY_CURRENT_USER, L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify" }));
		return events;
	}
}