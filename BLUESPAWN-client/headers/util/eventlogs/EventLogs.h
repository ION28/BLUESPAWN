#pragma once   

#include "windows.h"
#include <string>
#include <sddl.h>
#include <stdio.h>
#include <winevt.h>
#include "hunt/reaction/Reaction.h"
#include "hunt/reaction/HuntTrigger.h"
#include <set>
#include "util/eventlogs/EventSubscription.h"

#pragma comment(lib, "wevtapi.lib")

#define ARRAY_SIZE 10
#define TIMEOUT 1000  // 1 second; Set and use in place of INFINITE in EvtNext call

class EventLogs {
	public:
		static EventLogs* getLogs() {
			if (!logs)
				logs = new EventLogs;
			return logs;
		}

		/**
		@ param channel the channel to look for the event log (exe, 'Microsoft-Windows-Sysmon/Operational')
		@param id the event ID to filter for
		@param reaction the reaction to use when an event is detected
		@return the number of events detected, or -1 if something went wrong.
		*/
		int QueryEvents(const wchar_t* channel, unsigned int id, Reaction& reaction);

		/**
		@ param channel the channel to look for the event log (exe, 'Microsoft-Windows-Sysmon/Operational')
		@param id the event ID to filter for
		@param reaction the reaction to use when an event is detected
		@param params extra parameters to print in the output
		@return the number of events detected, or -1 if something went wrong.
		*/
		int QueryEvents(const wchar_t* channel, unsigned int id, std::set<std::wstring>& params, Reaction& reaction);

		DWORD GetEventParam(EVT_HANDLE hEvent, std::wstring* value, std::wstring param);
		DWORD GetEventXML(EVT_HANDLE hEvent, std::wstring* data);

		DWORD EventToDetection(EVT_HANDLE hEvent, EVENT_DETECTION * pDetection, std::set<std::wstring>& params);

		DWORD subscribe(LPWSTR pwsPath, unsigned int id, std::shared_ptr<Reactions::HuntTriggerReaction> reaction);

	private:
		DWORD ProcessResults(EVT_HANDLE hResults, Reaction& reaction, int* numFound, std::set<std::wstring>& params);

		EventLogs() {};
		static EventLogs* logs;

		std::vector<std::shared_ptr<EventSubscription>> subscriptionList;
};