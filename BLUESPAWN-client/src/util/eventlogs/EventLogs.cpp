#include "util/eventlogs/EventLogs.h"
#include "common/StringUtils.h"
#include "hunt/reaction/Detections.h"
#include "util/log/Log.h"

const int SIZE_DATA = 4096;

DWORD GetEventParam(EVT_HANDLE hEvent, std::wstring* value, std::wstring param)
{
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
		LOG_ERROR("EvtCreateRenderContext failed with " + std::to_string(status));
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
				LOG_ERROR("GetEventParam malloc failed");
				status = ERROR_OUTOFMEMORY;
				goto cleanup;
			}
		}

		if (ERROR_SUCCESS != (status = GetLastError()))
		{
			LOG_ERROR("EvtRender in GetEventParam failed with " + std::to_string(status));
			goto cleanup;
		}
	}

	/*
	Table of variant members found here: https://docs.microsoft.com/en-us/windows/win32/api/winevt/ns-winevt-evt_variant
	Table of type values found here: https://docs.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_variant_type
	*/
	if (pRenderedValues[0].Type == EvtVarTypeString)
		*value  = std::wstring(pRenderedValues[0].StringVal);
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
	else if(pRenderedValues[0].Type == EvtVarTypeNull)
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

DWORD GetEventXML(EVT_HANDLE hEvent, std::wstring * data)
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
				LOG_ERROR("GetEventXML malloc failed");
				status = ERROR_OUTOFMEMORY;
				goto cleanup;
			}
		}

		if (ERROR_SUCCESS != (status = GetLastError()))
		{
			LOG_ERROR("EvtRender in GetEventXML failed with " + std::to_string(GetLastError()));
			goto cleanup;
		}
	}

	*data = std::wstring(pRenderedContent);

cleanup:

	return status;
}

// Enumerate all the events in the result set. 
DWORD ProcessResults(EVT_HANDLE hResults, Reaction& reaction, int* numFound, std::set<std::wstring> &params)
{
	DWORD status = ERROR_SUCCESS;
	EVT_HANDLE hEvents[ARRAY_SIZE];
	DWORD dwReturned = 0;

	while (true)
	{
		// Get a block of events from the result set.
		if (!EvtNext(hResults, ARRAY_SIZE, hEvents, INFINITE, 0, &dwReturned))
		{
			if (ERROR_NO_MORE_ITEMS != (status = GetLastError()))
			{
				LOG_ERROR("EvtNext failed with " + std::to_string(status));
			}

			goto cleanup;
		}

		// For each event, call the PrintEvent function which renders the
		// event for display. PrintEvent is shown in RenderingEvents.
		std::wstring eventIDStr;
		std::wstring eventRecordIDStr;
		std::wstring timeCreated;
		std::wstring channel;
		std::wstring rawXML;
		for (DWORD i = 0; i < dwReturned; i++)
		{
			if (ERROR_SUCCESS != (status = GetEventParam(hEvents[i], &eventIDStr, L"Event/System/EventID")))
				goto cleanup;
			if (ERROR_SUCCESS != (status = GetEventParam(hEvents[i], &eventRecordIDStr, L"Event/System/EventRecordID")))
				goto cleanup;
			if (ERROR_SUCCESS != (status = GetEventParam(hEvents[i], &timeCreated, L"Event/System/TimeCreated/@SystemTime")))
				goto cleanup;
			if (ERROR_SUCCESS != (status = GetEventParam(hEvents[i], &channel, L"Event/System/Channel")))
				goto cleanup;
			if (ERROR_SUCCESS != (status = GetEventXML(hEvents[i], &rawXML)))
				goto cleanup;

			// Specify extra parameters
			std::unordered_map<std::wstring, std::wstring> extraParams;
			for (std::wstring key : params) {
				std::wstring val;
				if (ERROR_SUCCESS != (status = GetEventParam(hEvents[i], &val, key))) {
					LOG_ERROR(L"Failed query parameter " + key + L" with code " + std::to_wstring(status));
					goto cleanup;
				}

				extraParams.insert({ key, val });
			}

			EVENT_DETECTION detect(std::stoul(eventIDStr), std::stoul(eventRecordIDStr), timeCreated, channel, rawXML);
			detect.params = extraParams;
			reaction.EventIdentified(std::make_shared<EVENT_DETECTION>(detect));

			(*numFound) += 1;
			EvtClose(hEvents[i]);
			hEvents[i] = NULL;

		}
	}

cleanup:

	for (DWORD i = 0; i < dwReturned; i++)
	{
		if (NULL != hEvents[i])
			EvtClose(hEvents[i]);
	}

	if (status == ERROR_NO_MORE_ITEMS)
		return ERROR_SUCCESS;
	return status;
}

int QueryEvents(const wchar_t* channel, unsigned int id, Reaction& reaction)
{
	return QueryEvents(channel, id, std::set<std::wstring>(), reaction);
}

int QueryEvents(const wchar_t* channel, unsigned int id, std::set<std::wstring>& params, Reaction& reaction)
{
	DWORD status = ERROR_SUCCESS;
	EVT_HANDLE hResults = NULL;

	auto query = std::wstring(L"Event/System[EventID=") + std::to_wstring(id) + std::wstring(L"]");
	auto wquery = query.c_str();

	hResults = EvtQuery(NULL, channel, wquery, EvtQueryChannelPath | EvtQueryReverseDirection);
	if (NULL == hResults)
	{
		status = GetLastError();

		if (ERROR_EVT_CHANNEL_NOT_FOUND == status)
			LOG_ERROR("The channel was not found.");
		else if (ERROR_EVT_INVALID_QUERY == status)
			// You can call the EvtGetExtendedStatus function to try to get 
			// additional information as to what is wrong with the query.
			LOG_ERROR(L"The query " + query + L" is not valid.");
		else
			LOG_ERROR("EvtQuery failed with " + std::to_string(status));

		goto cleanup;
	}

	int numFound = 0;
	status = ProcessResults(hResults, reaction, &numFound, params);

cleanup:

	if (hResults)
		EvtClose(hResults);

	if (status == ERROR_SUCCESS)
		return numFound;
	return -1;
}