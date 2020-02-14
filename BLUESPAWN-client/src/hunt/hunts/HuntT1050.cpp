#include "hunt/hunts/HuntT1050.h"
#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"
#include "util/log/HuntLogMessage.h"
#include <util\filesystem\YaraScanner.h>

#include <iostream>

namespace Hunts {

	HuntT1050::HuntT1050() : Hunt(L"T1050 - New Service") {
		// TODO: update these categories
		dwSupportedScans = (DWORD) Aggressiveness::Intensive | (DWORD) Aggressiveness::Normal;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	int HuntT1050::ScanNormal(const Scope& scope, Reaction reaction) {
		LOG_INFO("Hunting for T1050 - New Service at level Intensive");
		reaction.BeginHunt(GET_INFO());

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

		auto& yara = YaraScanner::GetInstance();
		int detections = 0;

		// Find detections with YARA rules
		for (auto query : queryResults) {
			FileSystem::File file = FileSystem::File(query.GetProperty(L"Event/EventData/Data[@Name='ImagePath']"));
			YaraScanResult result = yara.ScanFile(file);

			if (!result) {
				if (result.vKnownBadRules.size() > 0) {
					detections++;
					reaction.EventIdentified(EventLogs::EventLogItemToDetection(query));
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

		// Look for PSExec services
		for (auto query : queryResults) {
			auto imageName = query.GetProperty(L"Event/EventData/Data[@Name='ServiceName']");
			if (imageName.find(L"PSEXESVC") != std::wstring::npos) {
				reaction.EventIdentified(EventLogs::EventLogItemToDetection(query));
				detections++;
			}
		}

		reaction.EndHunt();
		return detections;
	}

	int HuntT1050::ScanIntensive(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for T1050 - New Service at level Intensive");
		reaction.BeginHunt(GET_INFO());

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

		auto results = EventLogs::QueryEvents(L"System", 7045, queries);

		for (auto result : results) 
			reaction.EventIdentified(EventLogs::EventLogItemToDetection(result));

		reaction.EndHunt();
		return results.size();
	}

	std::vector<std::shared_ptr<Event>> HuntT1050::GetMonitoringEvents() {
		std::vector<std::shared_ptr<Event>> events;
		events.push_back(std::make_shared<EventLogEvent>(L"System", 7045));
		return events;
	}

}