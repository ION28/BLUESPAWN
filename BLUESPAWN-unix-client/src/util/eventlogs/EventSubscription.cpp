#include "util/eventlogs/EventSubscription.h"
#include "reaction/Detections.h"
#include "util/log/Log.h"
#include "util/eventlogs/EventLogs.h"

// The callback that receives the events that match the query criteria. 

EventSubscription::EventSubscription(std::function<void(EventLogs::EventLogItem)> callback) : callback(callback), hSubscription{ INVALID_HANDLE_VALUE } {}

void EventSubscription::setSubHandle(const EventLogs::EventWrapper& hSubscription) {
	this->hSubscription = hSubscription;
}