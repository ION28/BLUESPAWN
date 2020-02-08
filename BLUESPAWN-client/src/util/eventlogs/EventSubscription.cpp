#include "util/eventlogs/EventSubscription.h"
#include "hunt/reaction/Detections.h"
#include "util/log/Log.h"
#include "util/eventlogs/EventLogs.h"

// The callback that receives the events that match the query criteria. 
DWORD WINAPI EventSubscription::SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, EVT_HANDLE hEvent) {
	DWORD status = ERROR_SUCCESS;

	EVENT_DETECTION detect(0, 0, L"", L"", L"");

	switch (action)
	{
		// You should only get the EvtSubscribeActionError action if your subscription flags 
		// includes EvtSubscribeStrict and the channel contains missing event records.
	case EvtSubscribeActionError:
		if (ERROR_EVT_QUERY_RESULT_STALE == (DWORD)hEvent)
		{
			LOG_ERROR("EventSubscription::SubscriptionCallback: The subscription callback was notified that event records are missing");
			// Handle if this is an issue for your application.
		}
		else
		{
			LOG_ERROR("EventSubscription::SubscriptionCallback: The subscription callback received the following Win32 error: " + std::to_string((int)hEvent));
		}
		break;

	case EvtSubscribeActionDeliver:
		if (ERROR_SUCCESS != (status = EventLogs::getLogs()->EventToDetection(hEvent, &detect, std::set<std::wstring>())))
			goto cleanup;
		reaction->EventIdentified(std::make_shared< EVENT_DETECTION>(detect));

		break;

	default:
		LOG_ERROR(L"EventSubscription::SubscriptionCallback: Unknown action.");
	}

cleanup:

	if (ERROR_SUCCESS != status)
	{
		// End subscription - Use some kind of IPC mechanism to signal
		// your application to close the subscription handle.
	}

	return status; // The service ignores the returned status.
}

EventSubscription::EventSubscription(Reactions::HuntTriggerReaction& reaction) {
	this->reaction = std::make_unique<Reactions::HuntTriggerReaction>(reaction);
}

EventSubscription::~EventSubscription() {
	if (hSubscription)
		EvtClose(hSubscription);
}

void EventSubscription::setSubHandle(EVT_HANDLE hSubscription) {
	this->hSubscription = hSubscription;
}