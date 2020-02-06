#pragma once   

#include "windows.h"
#include <string>
#include <iostream>
#include <stdio.h>
#include <winevt.h>
#include "hunt/Hunt.h"
#include "hunt/reaction/HuntTrigger.h"

#pragma comment(lib, "wevtapi.lib")

/**
A class used to connect a Hunt to the Windows async call when an event is generated
*/
class EventSubscription {
	public:
		EventSubscription(std::shared_ptr<Reactions::HuntTriggerReaction> reaction);
		DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, EVT_HANDLE hEvent);

	private:
		std::shared_ptr<Reactions::HuntTriggerReaction> reaction;
};