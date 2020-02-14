#pragma once

#include <vector>
#include <functional>
#include "hunt/reaction/Reaction.h"
#include "hunt/Scope.h"
#include "util/eventlogs/EventSubscription.h"
#include "util/eventlogs/XpathQuery.h"

enum class EventType {
	EventLog
};

class Event {
	public:
		EventType type;

		void addCallback(std::function<void(const Scope & scope, Reaction reaction)> callback);

		void setReaction(const Reaction& react);
		void setScope(const Scope& scope);

	protected:
		Event(EventType type);

		std::vector<std::function<void(const Scope & scope, Reaction reaction)>> callbacks;
		Reaction reaction;
		std::optional<Scope> scope;

};

class EventLogEvent : public Event {
	public:
		EventLogEvent(std::wstring channel, int eventID, std::vector<EventLogs::XpathQuery> queries = std::vector<EventLogs::XpathQuery>());

		std::function<void(EventLogs::EventLogItem)> eventLogTrigger;

		void setEventSub(std::unique_ptr< EventSubscription> sub);

		std::wstring getChannel();
		int getEventID();
		std::vector<EventLogs::XpathQuery> getQueries();

	private:
		void eventLogCallback(EventLogs::EventLogItem item);
		std::unique_ptr< EventSubscription> eventSub;
		std::wstring channel;
		int eventID;
		std::vector<EventLogs::XpathQuery> queries;
};