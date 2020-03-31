#include "hunt/hunts/HuntT1099.h"
#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"
#include "util/log/HuntLogMessage.h"
#include <util\filesystem\YaraScanner.h>

#include <iostream>

namespace Hunts {

	HuntT1099::HuntT1099() : Hunt(L"T1099 - Timestomp") {
		dwCategoriesAffected = (DWORD) Category::Files | (DWORD) Category::Processes;
		dwSourcesInvolved = (DWORD) DataSource::EventLogs;
		dwTacticsUsed = (DWORD) Tactic::DefenseEvasion;
	}

	std::vector<std::shared_ptr<DETECTION>> HuntT1099::RunHunt(const Scope& scope) {
		HUNT_INIT();

		// Create existance queries so interesting data is output
		std::vector<EventLogs::XpathQuery> queries;
		auto param1 = EventLogs::ParamList();
		auto param2 = EventLogs::ParamList();
		auto param3 = EventLogs::ParamList();
		auto param4 = EventLogs::ParamList();
		auto param5 = EventLogs::ParamList();
		param1.push_back(std::make_pair(L"Name", L"'Image'"));
		param2.push_back(std::make_pair(L"Name", L"'ProcessId'"));
		param3.push_back(std::make_pair(L"Name", L"'TargetFilename'"));
		param4.push_back(std::make_pair(L"Name", L"'CreationUtcTime'"));
		param5.push_back(std::make_pair(L"Name", L"'PreviousCreationUtcTime'"));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param1));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param2));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param3));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param4));
		queries.push_back(EventLogs::XpathQuery(L"Event/EventData/Data", param5));

		auto queryResults = EventLogs::QueryEvents(L"Microsoft-Windows-Sysmon/Operational", 2, queries);

		// Find detections with YARA rules
		for (auto query : queryResults) {
			FileSystem::File file = FileSystem::File(query.GetProperty(L"Event/EventData/Data[@Name='TargetFilename']"));
			FILE_DETECTION(file.GetFilePath());

			// Scan process?
			/* HandleWrapper hProcess{ OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, std::stoi(query.GetProperty(L"Event/EventData/Data[@Name='ProcessId']"))) };
			if(hProcess){
				
			} */
		}

		HUNT_END();
	}

	std::vector<std::shared_ptr<Event>> HuntT1099::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;
		events.push_back(std::make_shared<EventLogEvent>(L"Microsoft-Windows-Sysmon/Operational", 2));
		return events;
	}
}