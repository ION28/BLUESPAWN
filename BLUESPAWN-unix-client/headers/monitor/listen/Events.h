
#include <atomic>

#define WAIT_OBJECT_0 0
#define INFINITE -1

namespace Events{

/**
 * A class capable of describing an event to subscribe to
 */ 
class EventHandle{

public:
    bool operator==(const EventHandle& e) const;

};

//an implementation of WaitForMultipleObjects to reduce overhead in the eventsListener class
int WaitForMultipleObjects(int nCount, const Events::EventHandle * lpHandles, bool bWaitAll, int dwMilliSeconds);

//for compatibility with the WaitForSingleObjects on the hManager event handle
bool WaitForSingleObject(std::atomic<bool> &hHandle, int dwMilliseconds);

};