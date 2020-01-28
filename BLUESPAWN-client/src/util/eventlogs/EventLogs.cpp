#include "util/eventlogs/EventLogs.h"
#include "common/StringUtils.h"

const int SIZE_DATA = 4096;
TCHAR XMLDataCurrent[SIZE_DATA];

int QueryEvents(const wchar_t* channel, unsigned int id, Reaction reaction)
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

	return 5;

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
	LPWSTR pRenderedContent = NULL;

	// Identify the components of the event that you want to render. In this case,
	// render the provider's name and channel from the system section of the event.
	// To get user data from the event, you can specify an expression such as
	// L"Event/EventData/Data[@Name=\"<data name goes here>\"]".
	//hContext = EvtCreateRenderContext(count, (LPCWSTR*)ppValues, EvtRenderContextValues);
	//hContext = EvtCreateRenderContext(count, (LPCWSTR*)ppValues, EvtRenderContextValues);
	/*if (NULL == hContext)
	{
		wprintf(L"EvtCreateRenderContext failed with %lu\n", status = GetLastError());
		goto cleanup;
	}*/

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
	//wprintf(L"\nProvider Name: %s\n", pRenderedValues[0].StringVal);
	ZeroMemory(XMLDataCurrent, SIZE_DATA);
	lstrcpyW(XMLDataCurrent, pRenderedContent);

	wprintf(L"EvtRender data %s\n", XMLDataCurrent);

cleanup:

	if (hContext)
		EvtClose(hContext);

	if (pRenderedValues)
		free(pRenderedValues);

	return status;
}
