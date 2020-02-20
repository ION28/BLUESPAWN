#include "hunt/hunts/HuntT1037.h"
#include "hunt/RegistryHunt.h"

#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"
#include <util\filesystem\YaraScanner.h>

using namespace Registry;

namespace Hunts {
	HuntT1037::HuntT1037() : Hunt(L"T1037 - Logon Scripts") {
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD)Category::Configurations | (DWORD)Category::Files;
		dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD)DataSource::FileSystem;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::LateralMovement;
	}

	int Hunts::HuntT1037::AnalyzeRegistryStartupKey(Reaction reaction) {
		std::map<RegistryKey, std::vector<RegistryValue>> keys;

		auto HKCUEnvironment = RegistryKey{ HKEY_CURRENT_USER, L"Environment", };
		keys.emplace(HKCUEnvironment, CheckValues(HKCUEnvironment, {
			{ L"UserInitMprLogonScript", RegistryType::REG_SZ_T, L"", false, CheckSzEmpty }
			}));

		int detections = 0;
		for (const auto& key : keys) {
			for (const auto& value : key.second) {
				reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(key.first.GetName(), value));
				detections++;

				auto& yara = YaraScanner::GetInstance();

				FileSystem::File file = FileSystem::File(value.ToString());

				std::vector<std::wstring> sus_exts = { L".bat", L".cmd", L".job", L".js", L".jse", L".lnk",
					L".sct", L".vb", L".vbe", L".vbs", L".vbscript" };

				if (std::find(sus_exts.begin(), sus_exts.end(), file.GetFileAttribs().extension) != sus_exts.end()) {
					detections++;
					reaction.FileIdentified(std::make_shared<FILE_DETECTION>(file.GetFilePath()));
				} else {
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
			}
		}

		return detections;
	}

	int Hunts::HuntT1037::AnalayzeStartupFolders(Reaction reaction) {
		//Need to check the following
		//C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\
		//C:\Users\USERNAME\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\StartUp\
		return 0;
	}

	int HuntT1037::ScanCursory(const Scope& scope, Reaction reaction) {
		LOG_INFO(L"Hunting for " << name << L" at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int detections = AnalyzeRegistryStartupKey(reaction);
		detections += AnalayzeStartupFolders(reaction);

		reaction.EndHunt();
		return detections;
	}
}