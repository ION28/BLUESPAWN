#include "hunt/hunts/HuntT1198.h"
#include "hunt/RegistryHunt.h"

#include "util/configurations/Registry.h"
#include "util/filesystem/Filesystem.h"
#include "util/log/Log.h"
#include "util/log/HuntLogMessage.h"
#include "util/processes/ProcessUtils.h"

#include "../resources/resource.h"

#include "common/Utils.h"

#include <queue>
#include <map>
#include <vector>

using namespace Registry;

namespace Hunts{

	HuntT1198::HuntT1198() : Hunt(L"T1198 - SIP and Trust Provider Hijacking"){
		dwSupportedScans = (DWORD) Aggressiveness::Normal;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence | (DWORD) Tactic::DefenseEvasion;
	}

	std::wstring GetResource(DWORD identifier){
		auto hRsrcInfo = FindResourceW(nullptr, MAKEINTRESOURCE(identifier), L"textfile");
		if(!hRsrcInfo){
			return { nullptr, 0 };
		}

		auto hRsrc = LoadResource(nullptr, hRsrcInfo);
		if(!hRsrc){
			return { nullptr, 0 };
		}

		return StringToWidestring({ reinterpret_cast<LPCSTR>(LockResource(hRsrc)), SizeofResource(nullptr, hRsrcInfo) });
	}

	std::map<std::wstring, std::map<std::wstring, std::pair<std::wstring, std::wstring>>> ParseResource(DWORD dwResourceID){
		auto resource{ GetResource(dwResourceID) };

		std::map<std::wstring, std::map<std::wstring, std::pair<std::wstring, std::wstring>>> map{};

		auto lines{ SplitStringW(resource, L"\n") };
		for(auto& line : lines){
			std::map<std::wstring, std::pair<std::wstring, std::wstring>> values;
			auto type{ line.substr(0, line.find(L":")) };
			auto entries{ SplitStringW(line.substr(line.find(L":") + 1), L" ") };
			for(auto& entry : entries){
				auto parts{ SplitStringW(entry, L",") };
				auto path{ FileSystem::SearchPathExecutable(parts[1]) };
				if(path){
					values.emplace(parts[0], std::pair<std::wstring, std::wstring>{ ToLowerCaseW(*path), parts[2] });
				} else{
					values.emplace(parts[0], std::pair<std::wstring, std::wstring>{ ToLowerCaseW(parts[1]), parts[2] });
				}
			}
			map.emplace(type, std::move(values));
		}

		return map;
	}

	int HuntT1198::ScanNormal(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for " << name << " at level Normal");
		reaction.BeginHunt(GET_INFO());

		int detections = 0;

		std::map<std::wstring, std::vector<std::pair<RegistryValue, std::wstring>>> files{};

		// Verify that the installed SIPs are good
		auto goodSIP{ ParseResource(GoodSIP) };
		for(auto keypath : { L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0", L"SOFTWARE\\WoW6432Node\\Microsoft\\Cryptography\\OID\\EncodingType 0" }){
			RegistryKey key{ HKEY_LOCAL_MACHINE, keypath };
			for(auto subkey : key.EnumerateSubkeyNames()){
				if(goodSIP.find(subkey) != goodSIP.end()){
					auto& entry{ goodSIP.at(subkey) };
					RegistryKey SIPType{ key, subkey };

					for(auto GUID : SIPType.EnumerateSubkeyNames()){
						RegistryKey GUIDInfo{ SIPType, GUID };
						auto dll{ GUIDInfo.GetValue<std::wstring>(L"Dll") };
						auto func{ GUIDInfo.GetValue<std::wstring>(L"FuncName") };
						GUID = GUID.substr(1, GUID.length() - 2);

						if(entry.find(GUID) != entry.end()){
							auto& pair{ entry.at(GUID) };
							if(func && func != pair.second){
								reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ GUIDInfo, L"FuncName", std::move(*func) }));
								detections++;
							}

							if(dll){
								if(files.find(*dll) == files.end()){
									files.emplace(*dll, std::vector<std::pair<RegistryValue, std::wstring>>{ std::pair<RegistryValue, std::wstring>{
										RegistryValue{ GUIDInfo, L"Dll", *GUIDInfo.GetValue<std::wstring>(L"Dll") },
										pair.first
									}});
								} else{
									files.at(*dll).emplace_back(std::pair<RegistryValue, std::wstring>{
										RegistryValue{ GUIDInfo, L"Dll", *GUIDInfo.GetValue<std::wstring>(L"Dll") },
										pair.first
									});
								}
							}
						} else {
							LOG_INFO("Nonstandard subject interface provider GUID " << GUID << " (DLL: " << *dll << ", Function: " << *func << ")");

							if(func){
								reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ GUIDInfo, L"FuncName", std::move(*func) }));
								detections++;
							}

							if(dll){
								auto path{ FileSystem::SearchPathExecutable(*dll) };
								if(path){
									reaction.FileIdentified(std::make_shared<FILE_DETECTION>(FileSystem::File{ *path }));
									detections++;
								}
								reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ GUIDInfo, L"Dll", std::move(*dll) }));
								detections++;
							}
						}
					}
				}
			}
		}

		// Verify that the installed Trust Providers are good
		auto goodTrustProviders{ ParseResource(GoodTrustProviders) };
		for(auto keypath : { L"SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust", L"SOFTWARE\\WoW6432Node\\Microsoft\\Cryptography\\Providers\\Trust" }){
			RegistryKey key{ HKEY_LOCAL_MACHINE, keypath };
			for(auto& subkey : key.EnumerateSubkeyNames()){
				if(goodTrustProviders.find(subkey) != goodTrustProviders.end()){
					auto& entry{ goodTrustProviders.at(subkey) };
					RegistryKey ProviderType{ key, subkey };

					for(auto& GUID : ProviderType.EnumerateSubkeyNames()){
						RegistryKey GUIDInfo{ ProviderType, GUID };
						auto dll{ GUIDInfo.GetValue<std::wstring>(L"$DLL") };
						auto func{ GUIDInfo.GetValue<std::wstring>(L"$Function") };
						GUID = GUID.substr(1, GUID.length() - 2);

						if(entry.find(GUID) != entry.end()){
							auto& pair{ entry.at(GUID) };
							if(func && func != pair.second){
								reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ GUIDInfo, L"$Function", std::move(*func) }));
								detections++;
							}

							if(files.find(*dll) == files.end()){
								files.emplace(*dll, std::vector<std::pair<RegistryValue, std::wstring>>{ std::pair<RegistryValue, std::wstring>{
									RegistryValue{ GUIDInfo, L"$DLL", *GUIDInfo.GetValue<std::wstring>(L"$DLL") },
										pair.first
								}});
							} else{
								files.at(*dll).emplace_back(std::pair<RegistryValue, std::wstring>{
									RegistryValue{ GUIDInfo, L"$DLL", *GUIDInfo.GetValue<std::wstring>(L"$DLL") },
										pair.first
								});
							}
						} else{
							LOG_INFO("Nonstandard trust provider GUID " << GUID << " for " << subkey << " (DLL: " << *dll << ", Function: " << *func << ")");

							if(func){
								reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ GUIDInfo, L"$Function", std::move(*func) }));
								detections++;
							}

							if(dll){
								auto path{ FileSystem::SearchPathExecutable(*dll) };
								if(path){
									reaction.FileIdentified(std::make_shared<FILE_DETECTION>(FileSystem::File{ *path }));
									detections++;
								}
								reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ GUIDInfo, L"$DLL", std::move(*dll) }));
								detections++;
							}
						}
					}
				}
			}
		}

		// Verify the collection of DLLs
		for(auto& pair : files){
			auto dllpath{ FileSystem::SearchPathExecutable(pair.first) };
			if(!dllpath){
				// Assume the worst - if the DLL path isn't found, it's because there's a target process that WILL find it
				for(auto& value : pair.second){
					LOG_INFO("DLL " << pair.first << " not found and may be a target for hijacking");
					reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(value.first));
					detections++;
				}
			} else{
				dllpath = ToLowerCaseW(*dllpath);
				auto location{ dllpath->find(L"syswow64") };
				if(location != std::wstring::npos){
					dllpath->replace(dllpath->begin() + location, dllpath->begin() + location + 8, L"system32");
				}
				for(auto& value : pair.second){
					if(dllpath != value.second && (dllpath->length() >= value.second.length() && 
												   dllpath->substr(dllpath->length() - value.second.length()) != value.second)){
						LOG_INFO("Path for dll " << *dllpath << " does not match " << value.second << " and may have been hijacked");
						reaction.FileIdentified(std::make_shared<FILE_DETECTION>(FileSystem::File{ *dllpath }));
						reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(value.first));
						detections += 2;
					}
				}
			}
		}

		// Ensure only Microsoft signed DLLs are used here
		std::vector<std::wstring> keypaths{
			L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0",
			L"SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust"
		};
		for(auto keypath : keypaths){
			for(auto key : CheckSubkeys(HKEY_LOCAL_MACHINE, keypath, true, false)){
				std::queue<RegistryKey> keys{};
				keys.emplace(key);

				while(keys.size()){
					auto check{ keys.front() };
					keys.pop();

					for(auto val : check.EnumerateValues()){
						auto type{ check.GetValueType(val) };
						if(type == RegistryType::REG_SZ_T || type == RegistryType::REG_EXPAND_SZ_T){
							auto path{ FileSystem::SearchPathExecutable(*check.GetValue<std::wstring>(val)) };
							if(path){
								auto file{ FileSystem::File(*path) };
								if(!file.IsMicrosoftSigned()){
									reaction.FileIdentified(std::make_shared<FILE_DETECTION>(file));
									reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ check, val, *check.GetValue<std::wstring>(val) }));
									detections += 2;
								}
							} else if(ToLowerCaseW(val).find(L"dll") != std::wstring::npos){
								reaction.RegistryKeyIdentified(std::make_shared<REGISTRY_DETECTION>(RegistryValue{ check, val, *check.GetValue<std::wstring>(val) }));
								detections++;
							}
						}
					}
					for(auto subkey : check.EnumerateSubkeys()){
						keys.emplace(subkey);
					}
				}
			}
		}

		reaction.EndHunt();
		return detections;
	}

	std::vector<std::shared_ptr<Event>> HuntT1198::GetMonitoringEvents(){
		std::vector<std::shared_ptr<Event>> events;

		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0", true, false, true));
		ADD_ALL_VECTOR(events, Registry::GetRegistryEvents(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust", true, false, true));

		return events;
	}
}