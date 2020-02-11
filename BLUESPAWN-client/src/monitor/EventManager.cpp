#include "monitor/EventManager.h"

#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"

EventManager EventManager::manager;

EventManager::EventManager() {

}

DWORD EventManager::subscribeToEvent(std::shared_ptr<Event> e, std::function<void(const Scope & scope, Reaction reaction)> callback) {
	DWORD status = ERROR_SUCCESS;

	e->addCallback(callback);

	if (e->type == EventType::EventLog) 
		status = EventManager::manager.setupEventLogEvent(e);

	EventManager::manager.eventList.push_back(e);

	return status;
}

DWORD EventManager::setupEventLogEvent(std::shared_ptr<Event> e) {
	auto logEvent = std::static_pointer_cast<EventLogEvent>(e);

	DWORD status;
	auto subscription = EventLogs::getLogs()->subscribe((LPWSTR)logEvent->getChannel().c_str(), logEvent->getEventID(), logEvent->eventLogTrigger, &status);
	logEvent->setEventSub(move(subscription));

	return status;
}