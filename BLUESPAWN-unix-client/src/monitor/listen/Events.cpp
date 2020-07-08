#include "Events.h"
#include <unistd.h>
#include <string.h>

namespace Events{

    bool EventHandle::operator==(const EventHandle& e) const{
        return this->details == e.details; //not sure if this method is actually needed
    }

    EventHandle::EventHandle(Events::EventDetails &details) : details{ details }{}

    bool EventHandle::HasSignal() {
        return !signalQueue.empty();
    }

    EventDetails EventHandle::PopSignal() {
        return signalQueue.pop();
    }

    void EventHandle::PushSignal(EventDetails details){
        signalQueue.push(details);
    }

    EventDetails::EventDetails(pid_t pid, long number, struct pt_regs * registers) : type{EventType::SystemCall}, pid{pid}, number{number}{
        if(!registers){
            memcpy(&this->registers, registers, sizeof(struct pt_regs));
        }
    }

    EventDetails::EventDetails(pid_t pid, std::string path, mode_t mode) : type{EventType::FileSystem}, pid{pid}, path{path}, mode{mode}{}

    EventDetails::EventDetails(pid_t pid, pid_t on, int signal) : type{EventType::ProcessSignal}, pid{pid}, on{on}, signal{signal}{}

    bool EventDetails::operator==(const EventDetails & other) const {
        if(type == EventType::FileSystem){
            return path == other.path && mode == other.mode;
        }else if(type == EventType::ProcessSignal){
            return signal == other.signal;
        }else if(type == EventType::SystemCall){
            return number == other.number;
        }
    }

    int WaitForMultipleObjects(int nCount, Events::EventHandle * lpHandles, bool bWaitAll, int dwMilliSeconds){
        //check through each handle
        //Again, dont really need the DW
        bool * done = new bool[nCount];
        int nDone = 0;
        while(true){
            for(int i = 0; i < nCount; i++){
                if(!done[i] && lpHandles[i].HasSignal()){
                    done[i] = true;
                    nDone ++;

                    if(!bWaitAll){
                        return i;
                    }
                }

            }

            if(bWaitAll && nDone == nCount){
                break;
            }
            usleep(10);
        }

        return nDone;
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