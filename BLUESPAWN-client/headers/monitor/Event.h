#pragma once

#include <vector>
#include <functional>
#include "hunt/reaction/Reaction.h"
#include "hunt/Scope.h"
#include "util/eventlogs/EventSubscription.h"

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
		EventLogEvent(std::wstring channel, int eventID);

		std::function<void(EVENT_DETECTION)> eventLogTrigger;

		void setEventSub(std::unique_ptr< EventSubscription> sub);

		std::wstring getChannel();
		int getEventID();

	private:
		void eventLogCallback(EVENT_DETECTION detection);
		std::unique_ptr< EventSubscription> eventSub;
		std::wstring channel;
		int eventID;
};