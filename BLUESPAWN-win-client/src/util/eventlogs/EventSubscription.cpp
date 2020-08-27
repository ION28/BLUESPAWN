#include "util/eventlogs/EventSubscription.h"
#include "util/log/Log.h"
#include "util/eventlogs/EventLogs.h"

// The callback that receives the events that match the query criteria. 
DWORD WINAPI EventSubscription::SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, EVT_HANDLE hEvent) {
	DWORD status = ERROR_SUCCESS;

	if(action == EvtSubscribeActionDeliver){
		auto item = EventLogs::EventToEventLogItem(hEvent, {});
		if(!item){
			return GetLastError();
		}
		callback(*item);
	} else {
		LOG_ERROR(L"EventSubscription::SubscriptionCallback: Unknown action.");
	}

	return ERROR_SUCCESS;
}

EventSubscription::EventSubscription(std::function<void(EventLogs::EventLogItem)> callback) : callback(callback), hSubscription{ INVALID_HANDLE_VALUE } {}

void EventSubscription::setSubHandle(const EventLogs::EventWrapper& hSubscription) {
	this->hSubscription = hSubscription;
}