#include "Events.h"
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <time.h>

namespace Events{

    EventHandle::EventHandle(){
        pthread_cond_init(&this->condition, NULL);
        pthread_mutex_init(&this->mutex, NULL);
        if(Events::currId == UINT_MAX){
            //TODO: fix this condition
            srand(time(NULL));
            this->id = rand();
        }
        else{
            this->id = Events::currId;
            Events::currId = Events::currId + 1;
        }
        
    }

    EventHandle::~EventHandle(){
        pthread_cond_destroy(&this->condition);
        pthread_mutex_destroy(&this->mutex);
    }

    void EventHandle::Set(){
        pthread_cond_signal(&this->condition);
    }

    int EventHandle::Wait(int timeout, bool * done){
        time_t current = time(NULL);
        pthread_mutex_lock(&this->mutex);
        int result = 0;
        if(timeout != INFINITE)
        {
            struct timespec spec;
            clock_gettime(CLOCK_REALTIME, &spec);
            spec.tv_sec += timeout;
            result = pthread_cond_timedwait(&this->condition, &this->mutex, &spec);
        }
        else
            result = pthread_cond_wait(&this->condition, &this->mutex);

        if(result == 0){
            *done = true;
        }
        
        return (int)(time(NULL) - current);
    }

    bool EventHandle::operator==(const EventHandle & other) const{
        return this->id == other.id;
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
        bool infinite = dwMilliSeconds == INFINITE;
        bool * done = new bool[nCount];
        int nDone = 0;
        while(true){
            for(int i = 0; i < nCount; i++){
                if(!done[i]){
                    bool odone = false;
                    if(infinite)
                        dwMilliSeconds -= lpHandles[i].Wait(dwMilliSeconds, &odone);
                    else
                        lpHandles[i].Wait(dwMilliSeconds, &odone);

                    if(odone){
                        nDone++;
                        done[i] = true;
                        if(bWaitAll){
                            break;
                        }
                    }
                    
                    
                    if(!infinite && dwMilliSeconds <= 0){
                        break;
                    }

                }
            }

            if(bWaitAll && nDone == nCount){
                break;
            }
        }

        return nDone;
    }

    bool WaitForSingleObject(Events::EventHandle * hHandle, int dwMilliseconds){
        return WaitForMultipleObjects(1, hHandle, true, dwMilliseconds);
    }

    Events::EventHandle * CreateEvent(){
        return new Events::EventHandle();
    }

    void SetEvent(Events::EventHandle *handle){
        handle->Set();
    }

    void CloseHandle(Events::EventHandle * handle){
        delete handle;
    }



};