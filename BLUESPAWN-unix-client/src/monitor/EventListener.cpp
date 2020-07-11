#include "monitor/EventListener.h"

#include "common/wrappers.hpp"
#include "util/log/Log.h"

void EventListener::SubEventListener::HandleEventNotify(Events::EventHandle hEvent){
    if(map.find(hEvent) != map.end()){
        for(auto& func : map.at(hEvent)){
            func();
        }
    }
}

void EventListener::SubEventListener::ListenForEvents(){
    while(true){

        // Enter a critical section to ensure this function isn't accessing data that isn't ready
        pthread_mutex_lock(&hSection);
        auto slots{ events.size() };
        auto data{ events.data() };
        pthread_mutex_unlock(&hSection);

        // Wait on the manager and events
        auto status = WaitForMultipleObjects(slots, data, false, INFINITE);

        // Manager is triggered
        if(status == WAIT_OBJECT_0){
            LOG_VERBOSE(3, "Manager event has been signalled; restarting wait");

            // Trigger manager response
            //SetEvent(hManagerResponse);
            hManagerResponse.store(true);

            // If the thread should terminate, return
            if(terminate){
                return;
            }

            // Recalculate the number of slots and the events, begin wait again
            continue;
        }

        // Event has triggered a callback
        //TODO: fix this stuff so that WAIT_OBJECT_0 is actually implemented
        else if(status > WAIT_OBJECT_0 && status < WAIT_OBJECT_0 + slots){
            LOG_VERBOSE(1, "An event has been triggered; processing callbacks");

            // Handle the event notification
            //EnterCriticalSection(hSection);
            pthread_mutex_lock(&hSection);
            HandleEventNotify(events[status - WAIT_OBJECT_0]);
            pthread_mutex_unlock(&hSection);

            // Recalculate the number of slots and the events, begin wait again
            continue;
        }

        else {
            LOG_ERROR("Failed to wait on events with status " << std::hex << status << "; Error code " << errno);
            dwFailureCount++;
            if(dwFailureCount >= 5){
                LOG_ERROR("Five consecutive errors have occured in a SubEventListener; Abandoning " << slots - 1 << " events");
                return;
            }
        }
    }
}

EventListener::SubEventListener::SubEventListener() : 
    hManager{ false },
    hManagerResponse{ false },
    dwSlotsFree{ 0 }, //probably not needed
    dwFailureCount{ 0 },
    events{},
    terminate{ false },
    hThread{ &EventListener::SubEventListener::ListenForEvents, this }{
    events.emplace_back(hManager);
    pthread_mutex_init(&hSection, NULL);
}

EventListener::SubEventListener::~SubEventListener(){
    // Indicate that the thread should terminate next time hManager is set
    terminate = true;

    // Set hManager, terminating the thread. No need to wait on the response; the join
    // will take care of waiting the appropriate amount of time.
    //SetEvent(hManager);
    hManager.store(true);

    // Wait for the thread to finish
    hThread.join();

    pthread_mutex_destroy(&hSection);
}

bool EventListener::SubEventListener::TrySubscribe(
    const Events::EventHandle& hEvent,
    const std::vector<std::function<void()>>& callbacks
){
    // When reading or writing events, you must enter a critical section
    //pthread_mutex_lock(&hSection);

    auto lock{AcquireMutex(hSection)};
    // Check if event already has a subscription
    if(map.find(hEvent) != map.end()){
        LOG_WARNING("Event has already been subscribed to; combining callbacks. Note that it is recommended "
                    "that TryAddCallback be called instead of TrySubscribe to add callbacks");

        auto& eventcallbacks{ map.at(hEvent) };
        for(auto& callback : callbacks){
            eventcallbacks.emplace_back(callback);
        }

        return true;
    }

    if(dwSlotsFree > 0){
        // Set the manager event since we're writing to map 
        //SetEvent(hManager);

        auto status{ Events::WaitForSingleObject(hManagerResponse, INFINITE) };


        events.emplace_back(hEvent);
        map.emplace(std::move(std::pair<Events::EventHandle, std::vector<std::function<void()>>>{ hEvent, callbacks }));
        dwSlotsFree--;
        return true;
    }

    return false;
}

std::optional<std::vector<std::function<void()>>> EventListener::SubEventListener::GetSubscription(
    const Events::EventHandle& hEvent
) const {
    // Enter a critical section before reading `map`
    auto lock { AcquireMutex(hSection)};

    auto result{ map.find(hEvent) };
    if(result == map.end()){
        return std::nullopt;
    }

    return map.at(hEvent);
}

bool EventListener::SubEventListener::TryAddCallback(
    const Events::EventHandle& hEvent,
    const std::function<void()>& callback
){
    // Enter a critical section before reading `map`
    auto lock{ AcquireMutex(hSection) };
    auto result{ map.find(hEvent) };
    if(result == map.end()){
        return false;
    }

    // Modification is allowed without setting hManager because it doesn't change
    // the dwSlotsFree or ordering of elements in map or events
    map.at(hEvent).push_back(callback);
    return true;
}

// Function adopted from https://stackoverflow.com/questions/20833453/comparing-stdfunctions-for-equality
void* getAddress(std::function<void()> f){
    return reinterpret_cast<void*>(f.template target<void()>()); //TODO
}

bool EventListener::SubEventListener::TryRemoveCallback(
    const Events::EventHandle& hEvent,
    const std::function<void()>& callback
){
    // Enter a critical section before reading `map`
    auto lock{ AcquireMutex(hSection) };

    auto result{ map.find(hEvent) };
    if(result == map.end()){
        return false;
    }

    auto& callbacks{ map.at(hEvent) };
    for(unsigned idx = 0; idx < callbacks.size(); idx++){

        // operator== is not defined for two std::functions; instead compare their addresses
        // Note that this does not check bound arguments
        if(getAddress(callbacks[idx]) == getAddress(callback)){

            // Modification of callbacks is allowed without setting hManager because it
            // doesn't change the dwSlotsFree or ordering of elements in map or events
            callbacks.erase(callbacks.begin() + idx);
            idx--;
        }
    }

    return true;
}

bool EventListener::SubEventListener::TryUnsubscribe(
    const Events::EventHandle& hEvent
){
    auto lock{ AcquireMutex(hSection) };

    auto result{ map.find(hEvent) };
    if(result == map.end()){
        return false;
    }

    // Set hManager before modifying events, map, or dwSlotsFree
    SetEvent(hManager);

    auto status{ Events::WaitForSingleObject(hManagerResponse, INFINITE) };

    map.erase(hEvent);
    for(unsigned idx = 0; idx < events.size(); idx++){
        if(events[idx] == hEvent){
            events.erase(events.begin() + idx);
            idx--;
        }
    }

    dwSlotsFree++;

    return true;
}

EventListener EventListener::instance{};

EventListener::EventListener() : subeventlisteners{}{}

EventListener& EventListener::GetInstance(){
    return instance;
}

bool EventListener::Subscribe(
    const Events::EventHandle& hEvent,
    const std::vector<std::function<void()>>& callbacks
){
    // Acquire lock before accessing subeventlisteners
    auto lock{ AcquireMutex(hSection) };

    for(auto& sublistener : subeventlisteners){
        // Try to subscribe to all subeventlisteners. It's O(n) time, but without a much more 
        // complicated structure, there's not really a better way. Even then, this O(n) is a 
        // fast O(n) and is likely faster than asymtotically better methods.
        if(sublistener->TrySubscribe(hEvent, callbacks)){
            return true;
        }
    }
    LOG_VERBOSE(1, "No sub-event listeners available; creating a new one");
    
    auto& listener{ std::make_unique<SubEventListener>() };
    auto success{ listener->TrySubscribe(hEvent, callbacks) };
    subeventlisteners.emplace_back(std::move(listener));

    if(!success){
        LOG_ERROR("Failed to add an event to an empty sub-event listener!");
        return false;
    }

    return true;
}

std::optional<std::vector<std::function<void()>>> EventListener::GetSubscription(
    const Events::EventHandle& hEvent
) const {
    // Acquire lock before accessing subeventlisteners
    auto lock{ AcquireMutex(hSection) };

    for(auto& sublistener : subeventlisteners){
        // See justification in EventListener::Subscribe
        if(auto& sub = sublistener->GetSubscription(hEvent)){
            return sub;
        }
    }

    LOG_WARNING("Unable to get subscription for event; Event may not have a subscription.");
    return std::nullopt;
}

bool EventListener::AddCallback(
    const Events::EventHandle& hEvent,
    const std::function<void()>& callback
){
    // Acquire lock before accessing subeventlisteners
    auto lock{ AcquireMutex(hSection) };

    for(auto& sublistener : subeventlisteners){
        // See justification in EventListener::Subscribe
        if(sublistener->TryAddCallback(hEvent, callback)){
            return true;
        }
    }

    LOG_ERROR("Unable to add callback to event; Event may not have a subscription.");
    return false;
}

bool EventListener::RemoveCallback(
    const Events::EventHandle& hEvent,
    const std::function<void()>& callback
){
    // Acquire lock before accessing subeventlisteners
    auto lock{ AcquireMutex(hSection) };

    for(auto& sublistener : subeventlisteners){
        // See justification in EventListener::Subscribe
        if(sublistener->TryRemoveCallback(hEvent, callback)){
            return true;
        }
    }

    LOG_ERROR("Unable to remove callback from event; Event may not have a subscription.");
    return false;
}

bool EventListener::Unsubscribe(
    const Events::EventHandle& hEvent
){
    // Acquire lock before accessing subeventlisteners
    auto lock{ AcquireMutex(hSection) };

    for(auto& sublistener : subeventlisteners){
        // See justification in EventListener::Subscribe
        if(sublistener->TryUnsubscribe(hEvent)){
            return true;
        }
    }

    LOG_ERROR("Unable to unsubscribe from event; Event may not have a subscription.");
    return false;
}