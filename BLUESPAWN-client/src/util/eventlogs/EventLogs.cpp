#include "util/eventlogs/EventLogs.h"
#include "common/StringUtils.h"
#include "hunt/reaction/Detections.h"
#include "util/log/Log.h"

const int SIZE_DATA = 4096;
const int ARRAY_SIZE = 10;

namespace EventLogs {

	/**
	The callback function directly called by event subscriptions.
	In turn it calls the EventSubscription::SubscriptionCallback of a specific class instance.
	*/
	DWORD WINAPI CallbackWrapper(EVT_SUBSCRIBE_NOTIFY_ACTION Action, PVOID UserContext, EVT_HANDLE Event) {
		return reinterpret_cast<EventSubscription*>(UserContext)->SubscriptionCallback(Action, Event);
	}

	DWORD EventLogs::GetEventParam(EVT_HANDLE hEvent, std::wstring* value, std::wstring param) {
		DWORD status = ERROR_SUCCESS;
		EVT_HANDLE hContext = NULL;
		DWORD dwBufferSize = 0;
		DWORD dwBufferUsed = 0;
		DWORD dwPropertyCount = 0;
		PEVT_VARIANT pRenderedValues = NULL;
		LPWSTR queryParam = (LPWSTR)(param.c_str());
		LPWSTR ppValues[] = { queryParam };
		DWORD count = sizeof(ppValues) / sizeof(LPWSTR);

		// Identify the components of the event that you want to render. In this case,
		// render the provider's name and channel from the system section of the event.
		// To get user data from the event, you can specify an expression such as
		// L"Event/EventData/Data[@Name=\"<data name goes here>\"]".
		hContext = EvtCreateRenderContext(count, (LPCWSTR*)ppValues, EvtRenderContextValues);
		if (NULL == hContext)
		{
			status = GetLastError();
			LOG_ERROR("EventLogs::GetEventParam: EvtCreateRenderContext failed with " + std::to_string(status));
			goto cleanup;
		}

		// The function returns an array of variant values for each element or attribute that
		// you want to retrieve from the event. The values are returned in the same order as 
		// you requested them.
		if (!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount))
		{
			if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
			{
				dwBufferSize = dwBufferUsed;
				pRenderedValues = (PEVT_VARIANT)malloc(dwBufferSize);
				if (pRenderedValues)
				{
					EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount);
				}
				else
				{
					LOG_ERROR("EventLogs::GetEventParam: GetEventParam malloc failed");
					status = ERROR_OUTOFMEMORY;
					goto cleanup;
				}
			}

			if (ERROR_SUCCESS != (status = GetLastError()))
			{
				LOG_ERROR("EventLogs::GetEventParam: EvtRender in GetEventParam failed with " + std::to_string(status));
				goto cleanup;
			}
		}

		/*
		Table of variant members found here: https://docs.microsoft.com/en-us/windows/win32/api/winevt/ns-winevt-evt_variant
		Table of type values found here: https://docs.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_variant_type
		*/
		if (pRenderedValues[0].Type == EvtVarTypeString)
			*value = std::wstring(pRenderedValues[0].StringVal);
		else if (pRenderedValues[0].Type == EvtVarTypeFileTime) {
			wchar_t ar[30];
			_ui64tow(pRenderedValues[0].FileTimeVal, ar, 10);
			*value = std::wstring(ar);
		}
		else if (pRenderedValues[0].Type == EvtVarTypeUInt16) {
			*value = std::to_wstring(pRenderedValues[0].UInt16Val);
		}
		else if (pRenderedValues[0].Type == EvtVarTypeUInt64) {
			*value = std::to_wstring(pRenderedValues[0].UInt64Val);
		}
		else if (pRenderedValues[0].Type == EvtVarTypeNull)
			*value = std::wstring(L"NULL");
		else {
			*value = std::wstring(L"Unknown VARIANT: " + std::to_wstring(pRenderedValues[0].Type));
		}


	cleanup:

		if (hContext)
			EvtClose(hContext);

		if (pRenderedValues)
			free(pRenderedValues);

		return status;
	}

	DWORD EventLogs::GetEventXML(EVT_HANDLE hEvent, std::wstring* data)
	{
		DWORD status = ERROR_SUCCESS;
		DWORD dwBufferSize = 0;
		DWORD dwBufferUsed = 0;
		DWORD dwPropertyCount = 0;
		LPWSTR pRenderedContent = NULL;

		// The function returns an array of variant values for each element or attribute that
		// you want to retrieve from the event. The values are returned in the same order as 
		// you requested them.
		if (!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount))
		{
			if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
			{
				dwBufferSize = dwBufferUsed;
				pRenderedContent = (LPWSTR)malloc(dwBufferSize);
				if (pRenderedContent)
				{
					EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount);
				}
				else
				{
					LOG_ERROR("EventLogs::GetEventXML: GetEventXML malloc failed");
					status = ERROR_OUTOFMEMORY;
					goto cleanup;
				}
			}

			if (ERROR_SUCCESS != (status = GetLastError()))
			{
				LOG_ERROR("EventLogs::GetEventXML: EvtRender in GetEventXML failed with " + std::to_string(GetLastError()));
				goto cleanup;
			}
		}

		*data = std::wstring(pRenderedContent);

	cleanup:

		return status;
	}

	// Enumerate all the events in the result set. 
	std::vector<EventLogItem> EventLogs::ProcessResults(EVT_HANDLE hResults, std::vector<XpathQuery>& filters) {
		DWORD status = ERROR_SUCCESS;
		EVT_HANDLE hEvents[ARRAY_SIZE];
		DWORD dwReturned = 0;

		std::vector<EventLogItem> results;

		while (true)
		{
			// Get a block of events from the result set.
			if (!EvtNext(hResults, ARRAY_SIZE, hEvents, INFINITE, 0, &dwReturned)) {
				if (ERROR_NO_MORE_ITEMS != (status = GetLastError()))
					LOG_ERROR("EventLogs::ProcessResults: EvtNext failed with " + std::to_string(status));

				goto cleanup;
			}

			for (DWORD i = 0; i < dwReturned; i++) {
				EventLogItem detect;

				// Generate a list of all filters that searched by existance and not value
				std::vector<std::wstring > params;
				for (auto query : filters)
					if (!query.SearchesByValue())
						params.push_back(query.ToString());
				if (ERROR_SUCCESS != (status = EventToEventLogItem(hEvents[i], &detect, params)))
					goto cleanup;

				results.push_back(detect);

				EvtClose(hEvents[i]);
				hEvents[i] = NULL;

			}
		}

	cleanup:

		for (DWORD i = 0; i < dwReturned; i++)
			if (NULL != hEvents[i])
				EvtClose(hEvents[i]);

		return results;
	}

	DWORD EventLogs::EventToEventLogItem(EVT_HANDLE hEvent, EventLogItem* pItem, std::vector<std::wstring>& params) {
		DWORD status = ERROR_SUCCESS;

		std::wstring eventIDStr;
		std::wstring eventRecordIDStr;
		std::wstring timeCreated;
		std::wstring channel;
		std::wstring rawXML;

		if (ERROR_SUCCESS != (status = GetEventParam(hEvent, &eventIDStr, L"Event/System/EventID")))
			return status;
		if (ERROR_SUCCESS != (status = GetEventParam(hEvent, &eventRecordIDStr, L"Event/System/EventRecordID")))
			return status;
		if (ERROR_SUCCESS != (status = GetEventParam(hEvent, &timeCreated, L"Event/System/TimeCreated/@SystemTime")))
			return status;
		if (ERROR_SUCCESS != (status = GetEventParam(hEvent, &channel, L"Event/System/Channel")))
			return status;
		if (ERROR_SUCCESS != (status = GetEventXML(hEvent, &rawXML)))
			return status;

		// Provide values for filtered parameters
		for (std::wstring key : params) {
			std::wstring val;
			if (ERROR_SUCCESS != (status = GetEventParam(hEvent, &val, key))) {
				LOG_ERROR(L"EventLogs::EventToDetection: Failed query parameter " + key + L" with code " + std::to_wstring(status));
				return status;
			}

			pItem->SetProperty(key, val);
		}

		pItem->SetEventID(std::stoul(eventIDStr));
		pItem->SetEventRecordID(std::stoul(eventRecordIDStr));
		pItem->SetTimeCreated(timeCreated);
		pItem->SetChannel(channel);
		pItem->SetXML(rawXML);

		return status;
	}

	std::vector<EventLogItem>  EventLogs::QueryEvents(const wchar_t* channel, unsigned int id, std::vector<XpathQuery>& filters) {
		DWORD status = ERROR_SUCCESS;
		EVT_HANDLE hResults = NULL;

		std::vector<EventLogItem> items;

		auto query = std::wstring(L"Event/System[EventID=") + std::to_wstring(id) + std::wstring(L"]");
		for (auto param : filters)
			query += L" and " + param.ToString();
		auto wquery = query.c_str();

		hResults = EvtQuery(NULL, channel, wquery, EvtQueryChannelPath | EvtQueryReverseDirection);
		if (NULL == hResults) {
			status = GetLastError();

			if (ERROR_EVT_CHANNEL_NOT_FOUND == status)
				LOG_ERROR("EventLogs::QueryEvents: The channel was not found.");
			else if (ERROR_EVT_INVALID_QUERY == status)
				LOG_ERROR(L"EventLogs::QueryEvents: The query " + query + L" is not valid.");
			else
				LOG_ERROR("EventLogs::QueryEvents: EvtQuery failed with " + std::to_string(status));
		}
		else {
			items = ProcessResults(hResults, filters);
		}

		if (hResults)
			EvtClose(hResults);

		return items;
	}

	std::unique_ptr<EventSubscription> EventLogs::subscribe(LPWSTR pwsPath, unsigned int id, std::function<void(EventLogItem)> callback, DWORD* pStatus, std::vector<XpathQuery>& filters) {
		*pStatus = ERROR_SUCCESS;
		EVT_HANDLE hSubscription = NULL;

		auto query = std::wstring(L"Event/System[EventID=") + std::to_wstring(id) + std::wstring(L"]");
		for (auto param : filters)
			query += L" and " + param.ToString();
		auto wquery = query.c_str();

		auto eventSub = std::make_unique<EventSubscription>(callback);

		hSubscription = EvtSubscribe(NULL, NULL, pwsPath, wquery, NULL, reinterpret_cast<void*>(eventSub.get()),
			CallbackWrapper, EvtSubscribeToFutureEvents);
		eventSub->setSubHandle(hSubscription);

		if (hSubscription == NULL) {
			// Cleanup a failed subscription
			*pStatus = GetLastError();

			if (ERROR_EVT_CHANNEL_NOT_FOUND == *pStatus)
				LOG_ERROR("EventLogs::subscribe: Channel was not found.");
			else if (ERROR_EVT_INVALID_QUERY == *pStatus)
				LOG_ERROR(L"EventLogs::subscribe: query " + query + L" is not valid.");
			else
				LOG_ERROR("EventLogs::subscribe: EvtSubscribe failed with " + std::to_string(*pStatus));
		}

		return eventSub;
	}

	std::shared_ptr<EVENT_DETECTION> EventLogs::EventLogItemToDetection(EventLogItem& pItem) {
		auto detect = std::make_shared<EVENT_DETECTION>(0, 0, L"", L"", L"");

		detect->eventID = pItem.GetEventID();
		detect->channel = pItem.GetChannel();
		detect->eventRecordID = pItem.GetEventRecordID();
		detect->timeCreated = pItem.GetTimeCreated();
		detect->rawXML = pItem.GetXML();
		detect->params = pItem.GetProperties();

		return detect;
	}

}