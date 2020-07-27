#pragma once   

#include "windows.h"
#include <stdio.h>
#include <winevt.h>
#include <functional>
#include "scan/Detections.h"
#include "util/eventlogs/EventLogItem.h"

#pragma comment(lib, "wevtapi.lib")

/**
* A class used to connect a HuntTriggerReaction to the Windows async call when an event is generated
*/
class EventSubscription {
	public:
		EventSubscription(std::function<void(EventLogs::EventLogItem)> callback);

		/**
		* The function called by the underlying Windows OS as a callback.
		* In turn calls reaction->EventIdentified
		*/
		DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, EVT_HANDLE hEvent);

		/**
		* Set the event handle so it can be closed when this object is deleted
		*/
		void setSubHandle(const EventLogs::EventWrapper& hSubscription);

	private:
		std::function<void(EventLogs::EventLogItem)> callback;
		EventLogs::EventWrapper hSubscription;
};