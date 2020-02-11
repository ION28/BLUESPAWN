#pragma once   

#include "windows.h"
#include <string>
#include <sddl.h>
#include <stdio.h>
#include <winevt.h>
#include "hunt/reaction/Reaction.h"
#include <vector>
#include "util/eventlogs/EventSubscription.h"
#include "util/eventlogs/EventLogItem.h"

#pragma comment(lib, "wevtapi.lib")

namespace EventLogs {

	typedef std::vector<std::pair<std::wstring, std::wstring>> ParamList;

	/**
	* @param channel the channel to look for the event log (exe, 'Microsoft-Windows-Sysmon/Operational')
	* @param id the event ID to filter for
	* @param reaction the reaction to use when an event is detected
	* @param params extra parameters to print in the output
	* @return the number of events detected, or -1 if something went wrong.
	*/
	std::vector<EventLogItem> QueryEvents(const wchar_t* channel, unsigned int id, ParamList& params = ParamList());

	/**
	* Get the string value of a parameter in an event
	*
	* @param hEvent a handle to an event
	* @param value a pointer to a wstring where the parameter value will be stored
	* @param param the parameter whose value is being queried. Must be a valud XPATH query
	* @return the status of the operation
	*/
	DWORD GetEventParam(EVT_HANDLE hEvent, std::wstring* value, std::wstring param);
	/**
	* Get the XML representation of an event
	*
	* @param hEvent a handle to an event
	* @param data pointer to a wstring where the XML result will be stored
	* @return the status of the operation
	*/
	DWORD GetEventXML(EVT_HANDLE hEvent, std::wstring* data);

	/**
	* Create an EVENT_DETECTION struct from an event handle
	*
	* @param hEvent the handle being turned into a detection object
	* @param pDetection a pointer to the detection struct to store the results
	* @param params a list of XPATH parameters to include optionally in the struct
	* @return the status of the operation
	*/
	DWORD EventToEventLogItem(EVT_HANDLE hEvent, EventLogItem* pItem, std::vector<std::wstring>& params);

	std::shared_ptr<EVENT_DETECTION> EventLogItemToDetection(EventLogItem& pItem);

	/**
	* Subscribe a HuntTriggerReaction to a specific Windows event
	*
	* @param pwsPath the event channel to subscribe to
	* @param id the id of the event to subscribe to
	* @param reaction the reaction to call when an event is generated
	* @param status the status of the operation
	* @returns a shared pointer to the datasturctures storing the event subscription information
	*/
	std::unique_ptr<EventSubscription> subscribe(LPWSTR pwsPath, unsigned int id, std::function<void(EventLogItem)> callback, DWORD* status);

	std::vector<EventLogItem> ProcessResults(EVT_HANDLE hResults, ParamList& params);


}