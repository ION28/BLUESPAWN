#pragma once

#include <atomic>
#include <pthread.h>

#include "util/ThreadsafeQueue.h"

#define WAIT_OBJECT_0 0
#define INFINITE -1

namespace Events{

/**
 * A class capable of describing an event to subscribe to
 * 
 */ 
class EventHandle{
private:
    ThreadsafeQueue<EventDetails> signalQueue;

public:

    EventHandle();

    ~EventHandle();

    bool operator==(const EventHandle& e) const;

};

//an implementation of WaitForMultipleObjects to reduce overhead in the eventsListener class
int WaitForMultipleObjects(int nCount, const Events::EventHandle * lpHandles, bool bWaitAll, int dwMilliSeconds);

//for compatibility with the WaitForSingleObjects on the hManager event handle
bool WaitForSingleObject(std::atomic<bool> &hHandle, int dwMilliseconds);
//holds dynamic event details
class EventDetails{

};

};
