#pragma once   

#include "windows.h"
#include <stdio.h>
#include <winevt.h>
#include "hunt/reaction/HuntTrigger.h"

#pragma comment(lib, "wevtapi.lib")

/**
* A class used to connect a HuntTriggerReaction to the Windows async call when an event is generated
*/
class EventSubscription {
	public:
		EventSubscription(Reactions::HuntTriggerReaction& reaction);
		// Have a destructor to ensure we can clean up when this object is deleted
		~EventSubscription();

		/**
		* The function called by the underlying Windows OS as a callback.
		* In turn calls reaction->EventIdentified
		*/
		DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, EVT_HANDLE hEvent);

		/**
		* Set the event handle so it can be closed when this object is deleted
		*/
		void setSubHandle(EVT_HANDLE hSubscription);

	private:
		std::unique_ptr<Reactions::HuntTriggerReaction> reaction;
		EVT_HANDLE hSubscription;
};