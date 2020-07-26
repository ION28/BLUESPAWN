#pragma once   

#include "windows.h"
#include <string>
#include <sddl.h>
#include <stdio.h>
#include <winevt.h>
#include <vector>
#include "util/eventlogs/EventSubscription.h"
#include "util/eventlogs/EventLogItem.h"
#include "util/wrappers.hpp"
#include "XpathQuery.h"

#pragma comment(lib, "wevtapi.lib")

namespace EventLogs {

	typedef std::vector<std::pair<std::wstring, std::wstring>> ParamList;

	/**
	* @param channel the channel to look for the event log (exe, 'Microsoft-Windows-Sysmon/Operational')
	* @param id the event ID to filter for
	* @param params pair mappings of xpaths to values to filter the event log results by
	* @return the number of events detected, or -1 if something went wrong.
	*/
	std::vector<EventLogItem> QueryEvents(const std::wstring& channel, unsigned int id, const std::vector<XpathQuery>& filters = {});

	/**
	* Get the string value of a parameter in an event
	*
	* @param hEvent a handle to an event
	* @param value a pointer to a wstring where the parameter value will be stored
	* @param param the parameter whose value is being queried. Must be a valud XPATH query
	* @return the status of the operation
	*/
	std::optional<std::wstring> GetEventParam(const EventWrapper& hEvent, const std::wstring& param);
	/**
	* Get the XML representation of an event
	*
	* @param hEvent a handle to an event
	* @param data pointer to a wstring where the XML result will be stored
	* @return the status of the operation
	*/
	std::optional<std::wstring> GetEventXML(const EventWrapper& hEvent);

	/**
	* Create an EVENT_DETECTION struct from an event handle
	*
	* @param hEvent the handle being turned into a detection object
	* @param pDetection a pointer to the detection struct to store the results
	* @param params a list of XPATH parameters to include optionally in the struct
	* @return the status of the operation
	*/
	std::optional<EventLogItem> EventToEventLogItem(const EventWrapper& hEvent, const std::vector<std::wstring>& params);

	Detection EventLogItemToDetection(const EventLogItem& pItem);

	/**
	* Subscribe a HuntTriggerReaction to a specific Windows event
	*
	* @param pwsPath the event channel to subscribe to
	* @param id the id of the event to subscribe to
	* @param callback the function to call when event subscriptions are returned
	* @param status the status of the operation
	* @returns a shared pointer to the datasturctures storing the event subscription information
	*/
	std::optional<std::reference_wrapper<EventSubscription>> SubscribeToEvent(const std::wstring& pwsPath, unsigned int id, const std::function<void(EventLogItem)>& callback, const std::vector<XpathQuery>& filters = {});

	/**
	* A utility function called by QueryEvents
	*/
	std::vector<EventLogItem> ProcessResults(const EventWrapper& hEvent, const std::vector<XpathQuery>& filters);

	bool IsChannelOpen(const std::wstring& channel);
	bool OpenChannel(const std::wstring& channel);

}