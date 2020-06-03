#include "util/eventlogs/EventSubscription.h"
#include "reaction/Detections.h"
#include "util/log/Log.h"
#include "util/eventlogs/EventLogs.h"

// The callback that receives the events that match the query criteria. 
unsigned int WINAPI EventSubscription::SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, EVT_HANDLE hEvent) {
	unsigned int status = ERROR_SUCCESS;

	if(action == EvtSubscribeActionDeliver){
		auto item = EventLogs::EventToEventLogItem(hEvent, {});
		if(!item){
			return errno;
		}
		callback(*item);
	} else {
		LOG_ERROR("EventSubscription::SubscriptionCallback: Unknown action.");
	}

	return ERROR_SUCCESS;
}

EventSubscription::EventSubscription(std::function<void(EventLogs::EventLogItem)> callback) : callback(callback), hSubscription{ INVALID_HANDLE_VALUE } {}

void EventSubscription::setSubHandle(const EventLogs::EventWrapper& hSubscription) {
	this->hSubscription = hSubscription;
}