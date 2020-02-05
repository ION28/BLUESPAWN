#include "util/eventlogs/EventSubscription.h"
#include "hunt/reaction/Detections.h"
#include "util/log/Log.h"
#include "util/eventlogs/EventLogs.h"

// The callback that receives the events that match the query criteria. 
DWORD WINAPI EventSubscription::SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, EVT_HANDLE hEvent) {
	DWORD status = ERROR_SUCCESS;

	std::wstring data;

	switch (action)
	{
		// You should only get the EvtSubscribeActionError action if your subscription flags 
		// includes EvtSubscribeStrict and the channel contains missing event records.
	case EvtSubscribeActionError:
		if (ERROR_EVT_QUERY_RESULT_STALE == (DWORD)hEvent)
		{
			wprintf(L"The subscription callback was notified that event records are missing.\n");
			// Handle if this is an issue for your application.
		}
		else
		{
			wprintf(L"The subscription callback received the following Win32 error: %lu\n", (DWORD)hEvent);
		}
		break;

	case EvtSubscribeActionDeliver:
		if (ERROR_SUCCESS != (status = EventLogs::getLogs()->GetEventXML(hEvent, &data)))
		{
			goto cleanup;
		}
		std::wcout << data << std::endl;
		break;

	default:
		wprintf(L"SubscriptionCallback: Unknown action.\n");
	}

cleanup:

	if (ERROR_SUCCESS != status)
	{
		// End subscription - Use some kind of IPC mechanism to signal
		// your application to close the subscription handle.
	}

	return status; // The service ignores the returned status.
}

EventSubscription::EventSubscription(Reaction& reaction) : reaction(reaction) {}