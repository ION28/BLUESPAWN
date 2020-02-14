#include "monitor/Event.h"
#include "hunt/reaction/Log.h"

Event::Event(EventType type) : type(type) {}

void Event::setReaction(const Reaction& react) {
	this->reaction = react;
}

void Event::setScope(const Scope& scope) {
	this->scope = std::optional<Scope>{ scope };
}

void Event::addCallback(std::function<void(const Scope & scope, Reaction reaction)> callback) {
	this->callbacks.push_back(callback);
}

/************************
***   EventLogEvent   ***
*************************/
EventLogEvent::EventLogEvent(std::wstring channel, int eventID, std::vector<EventLogs::XpathQuery> queries) :
	Event(EventType::EventLog) , channel(channel), eventID(eventID), queries(queries) {
	eventLogTrigger = std::bind(&EventLogEvent::eventLogCallback, this, std::placeholders::_1);
}

void EventLogEvent::eventLogCallback(EventLogs::EventLogItem item) {
	for (auto callback : this->callbacks)
		callback(Scope(), Reactions::LogReaction());
}

void EventLogEvent::setEventSub(std::unique_ptr< EventSubscription> sub) {
	this->eventSub = std::move(sub);
}

std::wstring EventLogEvent::getChannel() {
	return channel;
}
int EventLogEvent::getEventID() {
	return eventID;
}

std::vector<EventLogs::XpathQuery> EventLogEvent::getQueries() {
	return this->queries;
}