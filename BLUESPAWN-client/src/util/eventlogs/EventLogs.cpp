#include "util/eventlogs/EventLogs.h"

void queryevent(void)
{
	DWORD status = ERROR_SUCCESS;
	EVT_HANDLE hResults = NULL;

	hResults = EvtQuery(NULL, L"Microsoft-Windows-Sysmon/Operational", L"Event/System[EventID=5]", EvtQueryChannelPath | EvtQueryReverseDirection);
	if (NULL == hResults)
	{
		status = GetLastError();

		if (ERROR_EVT_CHANNEL_NOT_FOUND == status)
			wprintf(L"The channel was not found.\n");
		else if (ERROR_EVT_INVALID_QUERY == status)
			// You can call the EvtGetExtendedStatus function to try to get 
			// additional information as to what is wrong with the query.
			wprintf(L"The query is not valid.\n");
		else
			wprintf(L"EvtQuery failed with %lu.\n", status);

		goto cleanup;
	}

	PrintResults(hResults);

cleanup:

	if (hResults)
		EvtClose(hResults);

}

// Enumerate all the events in the result set. 
DWORD PrintResults(EVT_HANDLE hResults)
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
				wprintf(L"EvtNext failed with %lu\n", status);
			}

			goto cleanup;
		}

		// For each event, call the PrintEvent function which renders the
		// event for display. PrintEvent is shown in RenderingEvents.
		for (DWORD i = 0; i < dwReturned; i++)
		{
			//if (ERROR_SUCCESS == (status = PrintEvent(hEvents[i])))
			//if (ERROR_SUCCESS == (status = PrintEventSystemData(hEvents[i])))
			if (ERROR_SUCCESS == (status = PrintEventValues(hEvents[i])))
			{
				EvtClose(hEvents[i]);
				hEvents[i] = NULL;
			}
			else
			{
				goto cleanup;
			}
		}
	}

cleanup:

	for (DWORD i = 0; i < dwReturned; i++)
	{
		if (NULL != hEvents[i])
			EvtClose(hEvents[i]);
	}

	return status;
}

DWORD PrintEvent(EVT_HANDLE hEvent)
{
	DWORD status = ERROR_SUCCESS;
	DWORD dwBufferSize = 0;
	DWORD dwBufferUsed = 0;
	DWORD dwPropertyCount = 0;
	LPWSTR pRenderedContent = NULL;

	// The EvtRenderEventXml flag tells EvtRender to render the event as an XML string.
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
				wprintf(L"malloc failed\n");
				status = ERROR_OUTOFMEMORY;
				goto cleanup;
			}
		}

		if (ERROR_SUCCESS != (status = GetLastError()))
		{
			wprintf(L"EvtRender failed with %d\n", GetLastError());
			goto cleanup;
		}
	}

	wprintf(L"\n\n%s", pRenderedContent);

cleanup:

	if (pRenderedContent)
		free(pRenderedContent);

	return status;
}

DWORD PrintEventSystemData(EVT_HANDLE hEvent)
{
	DWORD status = ERROR_SUCCESS;
	EVT_HANDLE hContext = NULL;
	DWORD dwBufferSize = 0;
	DWORD dwBufferUsed = 0;
	DWORD dwPropertyCount = 0;
	PEVT_VARIANT pRenderedValues = NULL;
	WCHAR wsGuid[50];
	LPWSTR pwsSid = NULL;
	ULONGLONG ullTimeStamp = 0;
	ULONGLONG ullNanoseconds = 0;
	SYSTEMTIME st;
	FILETIME ft;
	DWORD EventID;
	// Identify the components of the event that you want to render. In this case,
	// render the system section of the event.
	hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextValues);
	if (NULL == hContext)
	{
		wprintf(L"EvtCreateRenderContext failed with %lu\n", status = GetLastError());
		goto cleanup;
	}

	// When you render the user data or system section of the event, you must specify
	// the EvtRenderEventValues flag. The function returns an array of variant values 
	// for each element in the user data or system section of the event. For user data
	// or event data, the values are returned in the same order as the elements are 
	// defined in the event. For system data, the values are returned in the order defined
	// in the EVT_SYSTEM_PROPERTY_ID enumeration.
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
				wprintf(L"malloc failed\n");
				status = ERROR_OUTOFMEMORY;
				goto cleanup;
			}
		}

		if (ERROR_SUCCESS != (status = GetLastError()))
		{
			wprintf(L"EvtRender failed with %d\n", GetLastError());
			goto cleanup;
		}
	}

	// Print the values from the System section of the element.
	wprintf(L"Provider Name: %s\n", pRenderedValues[EvtSystemProviderName].StringVal);
	if (NULL != pRenderedValues[EvtSystemProviderGuid].GuidVal)
	{
		StringFromGUID2(*(pRenderedValues[EvtSystemProviderGuid].GuidVal), wsGuid, sizeof(wsGuid) / sizeof(WCHAR));
		wprintf(L"Provider Guid: %s\n", wsGuid);
	}
	else
	{
		wprintf(L"Provider Guid: NULL");
	}

	EventID = pRenderedValues[EvtSystemEventID].UInt16Val;
	
	if (EvtVarTypeNull != pRenderedValues[EvtSystemQualifiers].Type)
	{
		EventID = MAKELONG(pRenderedValues[EvtSystemEventID].UInt16Val, pRenderedValues[EvtSystemQualifiers].UInt16Val);
	}
	wprintf(L"EventID: %lu\n", EventID);

	wprintf(L"Version: %u\n", (EvtVarTypeNull == pRenderedValues[EvtSystemVersion].Type) ? 0 : pRenderedValues[EvtSystemVersion].ByteVal);
	wprintf(L"Level: %u\n", (EvtVarTypeNull == pRenderedValues[EvtSystemLevel].Type) ? 0 : pRenderedValues[EvtSystemLevel].ByteVal);
	wprintf(L"Task: %hu\n", (EvtVarTypeNull == pRenderedValues[EvtSystemTask].Type) ? 0 : pRenderedValues[EvtSystemTask].UInt16Val);
	wprintf(L"Opcode: %u\n", (EvtVarTypeNull == pRenderedValues[EvtSystemOpcode].Type) ? 0 : pRenderedValues[EvtSystemOpcode].ByteVal);
	wprintf(L"Keywords: 0x%I64x\n", pRenderedValues[EvtSystemKeywords].UInt64Val);

	ullTimeStamp = pRenderedValues[EvtSystemTimeCreated].FileTimeVal;
	ft.dwHighDateTime = (DWORD)((ullTimeStamp >> 32) & 0xFFFFFFFF);
	ft.dwLowDateTime = (DWORD)(ullTimeStamp & 0xFFFFFFFF);

	FileTimeToSystemTime(&ft, &st);
	ullNanoseconds = (ullTimeStamp % 10000000) * 100; // Display nanoseconds instead of milliseconds for higher resolution
	wprintf(L"TimeCreated SystemTime: %02d/%02d/%02d %02d:%02d:%02d.%I64u)\n",
		st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond, ullNanoseconds);

	wprintf(L"EventRecordID: %I64u\n", pRenderedValues[EvtSystemEventRecordId].UInt64Val);

	if (EvtVarTypeNull != pRenderedValues[EvtSystemActivityID].Type)
	{
		StringFromGUID2(*(pRenderedValues[EvtSystemActivityID].GuidVal), wsGuid, sizeof(wsGuid) / sizeof(WCHAR));
		wprintf(L"Correlation ActivityID: %s\n", wsGuid);
	}

	if (EvtVarTypeNull != pRenderedValues[EvtSystemRelatedActivityID].Type)
	{
		StringFromGUID2(*(pRenderedValues[EvtSystemRelatedActivityID].GuidVal), wsGuid, sizeof(wsGuid) / sizeof(WCHAR));
		wprintf(L"Correlation RelatedActivityID: %s\n", wsGuid);
	}

	wprintf(L"Execution ProcessID: %lu\n", pRenderedValues[EvtSystemProcessID].UInt32Val);
	wprintf(L"Execution ThreadID: %lu\n", pRenderedValues[EvtSystemThreadID].UInt32Val);
	wprintf(L"Channel: %s\n", (EvtVarTypeNull == pRenderedValues[EvtSystemChannel].Type) ? L"" : pRenderedValues[EvtSystemChannel].StringVal);
	wprintf(L"Computer: %s\n", pRenderedValues[EvtSystemComputer].StringVal);

	if (EvtVarTypeNull != pRenderedValues[EvtSystemUserID].Type)
	{
		if (ConvertSidToStringSid(pRenderedValues[EvtSystemUserID].SidVal, &pwsSid))
		{
			wprintf(L"Security UserID: %s\n", pwsSid);
			LocalFree(pwsSid);
		}
	}

cleanup:

	if (hContext)
		EvtClose(hContext);

	if (pRenderedValues)
		free(pRenderedValues);

	return status;
}

DWORD PrintEventValues(EVT_HANDLE hEvent)
{
	DWORD status = ERROR_SUCCESS;
	EVT_HANDLE hContext = NULL;
	DWORD dwBufferSize = 0;
	DWORD dwBufferUsed = 0;
	DWORD dwPropertyCount = 0;
	PEVT_VARIANT pRenderedValues = NULL;
	LPWSTR ppValues[] = { L"Event/System/Computer" };
	DWORD count = sizeof(ppValues) / sizeof(LPWSTR);

	// Identify the components of the event that you want to render. In this case,
	// render the provider's name and channel from the system section of the event.
	// To get user data from the event, you can specify an expression such as
	// L"Event/EventData/Data[@Name=\"<data name goes here>\"]".
	hContext = EvtCreateRenderContext(count, (LPCWSTR*)ppValues, EvtRenderContextValues);
	//hContext = EvtCreateRenderContext(count, (LPCWSTR*)ppValues, EvtRenderContextValues);
	if (NULL == hContext)
	{
		wprintf(L"EvtCreateRenderContext failed with %lu\n", status = GetLastError());
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
				wprintf(L"malloc failed\n");
				status = ERROR_OUTOFMEMORY;
				goto cleanup;
			}
		}

		if (ERROR_SUCCESS != (status = GetLastError()))
		{
			wprintf(L"EvtRender failed with %d\n", GetLastError());
			goto cleanup;
		}
	}

	// Print the selected values.
	wprintf(L"\nProvider Name: %s\n", pRenderedValues[0].StringVal);

cleanup:

	if (hContext)
		EvtClose(hContext);

	if (pRenderedValues)
		free(pRenderedValues);

	return status;
}
