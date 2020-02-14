#include "hunt/hunts/HuntT1015.h"
#include "hunt/RegistryHunt.h"

#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"
#include <util\filesystem\YaraScanner.h>

using namespace Registry;

namespace Hunts {
	HuntT1015::HuntT1015() : Hunt(L"T1015 - Accessibility Features") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory | (DWORD)Aggressiveness::Normal;
		dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
		dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::PrivilegeEscalation;
	}

	int HuntT1015::EvaluateRegistry(Reaction reaction) {
		int detections = 0;

		// Check Registry Debuggers
		std::map<RegistryKey, std::vector<RegistryValue>> keys;

		std::wstring wsIFEO = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";
		std::wstring wsIFEOWow64 = L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";

		for (auto key : vAccessibilityBinaries) {
			auto subkey = RegistryKey{ HKEY_LOCAL_MACHINE, wsIFEO + key };
			auto subkey2 = RegistryKey{ HKEY_LOCAL_MACHINE, wsIFEOWow64 + key };

			keys.emplace(subkey, CheckValues(subkey, {
				{ L"Debugger", RegistryType::REG_SZ_T, L"", false, CheckSzEmpty },
				}));

			keys.emplace(subkey2, CheckValues(subkey2, {
				{ L"Debugger", RegistryType::REG_SZ_T, L"", false, CheckSzEmpty },
				}));
		}

		for (const auto& key : keys) {
			for (const auto& value : key.second) {
				reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(key.first.GetName(), value));
				LOG_INFO(key.first.GetName() << L" is configured with a Debugger value of " << value);
				detections++;
			}
		}

		return detections;
	}

	int HuntT1015::EvaluateFiles(Reaction reaction) {
		int detections = 0;

		auto& yara = YaraScanner::GetInstance();

		for (auto key : vAccessibilityBinaries) {
			FileSystem::File file = FileSystem::File(L"C:\\Windows\\System32\\" + key);
			YaraScanResult result = yara.ScanFile(file);

			if (!result) {
				if (result.vKnownBadRules.size() > 0) {
					detections++;
					reaction.FileIdentified(std::make_shared<FILE_DETECTION>(file.GetFilePath()));
				}
				for (auto identifier : result.vKnownBadRules) {
					LOG_INFO(file.GetFilePath() << L" matches known malicious identifier " << identifier);
				}
				for (auto identifier : result.vIndicatorRules) {
					LOG_INFO(file.GetFilePath() << L" matches known indicator identifier " << identifier);
				}
			}
		}

		return detections;
	}

	int HuntT1015::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO(L"Hunting for " << name  << L"at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int results = EvaluateRegistry(reaction);

		reaction.EndHunt();
		return results;
	}

	int HuntT1015::ScanNormal(const Scope& scope, Reaction reaction) {
		LOG_INFO(L"Hunting for " << name << L"at level Normal");
		reaction.BeginHunt(GET_INFO());


		int results = EvaluateRegistry(reaction);
		results += EvaluateFiles(reaction);
		
		reaction.EndHunt();
		return results;
	}
}
