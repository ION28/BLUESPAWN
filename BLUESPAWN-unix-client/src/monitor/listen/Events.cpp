#include "Events.h"
#include <unistd.h>

namespace Events{

    bool EventHandle::operator==(const EventHandle& e) const{
        return true;
    }


    int WaitForMultipleObjects(int nCount, const Events::EventHandle * lpHandles, bool bWaitAll, int dwMilliSeconds){
        //check through each handle
        //Again, dont really need the DW

    }

    bool WaitForSingleObject(std::atomic<bool> &hHandle, int dwMilliseconds){
        bool inf = dwMilliseconds == -1;

        //NOTE: for the purposes of this function, we dont actually need to implement dwMilliseconds
        //Going to leave it in here for possible future compatibility though.
        if(!inf){
            return false;
        }

        while(!hHandle)
        {
            usleep(10);
        }

        hHandle.store(false);
        return true;
    }

};