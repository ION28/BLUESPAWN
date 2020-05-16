#include "hunt/hunts/HuntT1122.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/filesystem/Filesystem.h"
#include "util/log/Log.h"
#include "util/log/HuntLogMessage.h"

#include "common/Utils.h"

#include <algorithm>

using namespace Registry;

namespace Hunts{

	HuntT1122::HuntT1122() : Hunt(L"T1122 - COM Hijacking"){
		dwSupportedScans = (DWORD) Aggressiveness::Intensive;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	int HuntT1122::ScanIntensive(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for " << name << " at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int detections = 0;

		std::map<std::wstring, std::vector<RegistryKey>> files{};

		for(auto key : CheckSubkeys(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID", true, true)){
			RegistryKey subkey{ key, L"InprocServer32" };
			if(subkey.Exists() && subkey.ValueExists(L"")){
				auto filename{ *subkey.GetValue<std::wstring>(L"") };
				auto path{ FileSystem::SearchPathExecutable(filename) };
				if(path){
					if(files.find(*path) != files.end()){
						files.at(*path).emplace_back(subkey);
					} else{
						files.emplace(*path, std::vector<RegistryKey>{ subkey });
					}
				}
			}
		}

		for(auto& pair : files){
			FileSystem::File file{ pair.first };
			if(file.GetFileExists() && !file.GetFileSigned()){
				for(auto& key : pair.second){
					auto path{ key.GetName() };
					RegistryValue value{ key, L"", *key.GetValue<std::wstring>(L"") };
					reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(value));
				}
				reaction.FileIdentified(std::make_shared<FILE_DETECTION>(file));
			}
		}

		reaction.EndHunt();
		return detections;
	}

	std::vector<std::shared_ptr<Event>> HuntT1122::GetMonitoringEvents(){
		std::vector<std::shared_ptr<Event>> events;

		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID", true, true, true));

		return events;
	}
}