#pragma once

#include <functional>
#include <string>
#include "hunt/reaction/Reaction.h"
#include "hunt/Scope.h"
#include "Event.h"
#include "util/eventlogs/EventSubscription.h"

class EventManager {

	public:
		static DWORD subscribeToEvent(std::shared_ptr<Event> e, std::function<void(const Scope & scope, Reaction reaction)> callback);

	private:
		EventManager();

		DWORD setupEventLogEvent(std::shared_ptr<Event> e);

		static EventManager manager;
		std::vector<std::shared_ptr<Event>> eventList;
};