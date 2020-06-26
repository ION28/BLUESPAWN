#include "hunt/hunts/HuntT1050.h"

#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"
#include "scan/ServiceScanner.h"
#include "scan/YaraScanner.h"

#include "common/Utils.h"
#include "common/StringUtils.h"

#include <iostream>
#include <set>

namespace Hunts {

	HuntT1050::HuntT1050() : Hunt(L"T1050 - New Service") {
		// TODO: update these categories
		dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
		dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	std::vector<EventLogs::EventLogItem> HuntT1050::Get7045Events() {
		// Create existance queries so interesting data is output
		std::vector<EventLogs::XpathQuery> queries;
		auto param1 = EventLogs::ParamList();
		auto param2 = EventLogs::ParamList();
		auto param3 = EventLogs::ParamList();
		auto param4 = EventLogs::ParamList();
		param1.push_back(std::make_pair(L"Name", L"'ServiceName'"));
		param2.push_back(std::make_pair(L"Name", L"'ImagePath'"));
		param3.push_back(std::make_pair(L"Name", L"'ServiceType'"));
		param4.push_back(std::make_pair(L"Name", L"'StartType'"));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param1));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param2));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param3));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param4));

		auto queryResults = EventLogs::QueryEvents(L"System", 7045, queries);

		return queryResults;
	}

	std::vector<std::reference_wrapper<Detection>> HuntT1050::RunHunt(const Scope& scope) {
		HUNT_INIT();

		auto queryResults = Get7045Events();

		std::set<std::pair<std::wstring, std::wstring>> services;
		
		for (auto result : queryResults) {
			auto imageName = result.GetProperty(L"Event/EventData/Data[@Name='ServiceName']");
			auto imagePath = ExpandEnvStringsW(result.GetProperty(L"Event/EventData/Data[@Name='ImagePath']"));

			// TODO: Command line parsing
			if(imagePath.find(L"\\system32\\svchost.exe") != std::wstring::npos){
				for(auto subkey : Registry::RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services" }.EnumerateSubkeys()){
					if(subkey.ValueExists(L"DisplayName") && subkey.GetValue<std::wstring>(L"DisplayName") == imageName){
						 auto params = Registry::RegistryKey{ subkey, L"Parameters" };
						 if(params.Exists() && params.ValueExists(L"ServiceDll")){
							 imagePath = *params.GetValue<std::wstring>(L"ServiceDll");
						 }
					}
				}
			}

			services.emplace(std::pair<std::wstring, std::wstring>{ imageName, imagePath });
		}

		for(const auto& service : services){
			SERVICE_DETECTION(service.first, service.second);
		}

		HUNT_END();
	}

	std::vector<std::unique_ptr<Event>> HuntT1050::GetMonitoringEvents() {
		std::vector<std::unique_ptr<Event>> events;

		events.push_back(std::make_unique<EventLogEvent>(L"System", 7045));
		Registry::GetRegistryEvents(events, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", false, false);

		return events;
	}

}