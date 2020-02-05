#pragma once   

#include "windows.h"
#include <string>
#include <iostream>
#include <stdio.h>
#include <winevt.h>
#include "hunt/reaction/Reaction.h"

#pragma comment(lib, "wevtapi.lib")

/**
A class used to connect Reaction objects with subscription callbacks
*/
class EventSubscription {
	public:
		EventSubscription(Reaction& reaction);
		DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, EVT_HANDLE hEvent);

	private:
		Reaction& reaction;
};