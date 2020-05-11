#include "monitor/EventListener.h"

#include "common/wrappers.hpp"
#include "util/log/Log.h"

void EventListener::SubEventListener::HandleEventNotify(HANDLE hEvent){
    if(map.find(hEvent) != map.end()){
        for(auto& func : map.at(hEvent)){
            func();
        }
    }
}

void EventListener::SubEventListener::ListenForEvents(){
    while(true){

        // Enter a critical section to ensure this function isn't accessing data that isn't ready
        EnterCriticalSection(hSection);
        auto slots{ MAXIMUM_WAIT_OBJECTS - dwSlotsFree };
        auto data{ events.data() };
        LeaveCriticalSection(hSection);

        // Wait on the manager and events
        auto status = WaitForMultipleObjects(slots, data, false, INFINITE);

        // Manager is triggered
        if(status == WAIT_OBJECT_0){
            LOG_VERBOSE(2, "Manager event has been signalled; restarting wait");

            // Trigger manager response
            SetEvent(hManagerResponse);

            // If the thread should terminate, return
            if(terminate){
                return;
            }

            // Recalculate the number of slots and the events, begin wait again
            continue;
        }

        // Event has triggered a callback
        else if(status > WAIT_OBJECT_0 && status < WAIT_OBJECT_0 + slots){
            LOG_VERBOSE(1, "An event has been triggered; processing callbacks");

            // Handle the event notification
            EnterCriticalSection(hSection);
            HandleEventNotify(events[status - WAIT_OBJECT_0 - 1]);
            LeaveCriticalSection(hSection);

            // Recalculate the number of slots and the events, begin wait again
            continue;
        }

        else {
            LOG_ERROR("Failed to wait on events with (status " << status << "); Error code " << GetLastError());
            dwFailureCount++;
            if(dwFailureCount >= 5){
                LOG_ERROR("Five consecutive errors have occured in a SubEventListener; Abandoning " << slots - 1 << " events");
                return;
            }
        }
    }
}

EventListener::SubEventListener::SubEventListener() : 
    hSection{},
    hManager{ CreateEventA(nullptr, false, false, nullptr) },
    hManagerResponse{ CreateEventA(nullptr, false, false, nullptr) },
    dwSlotsFree{ MAXIMUM_WAIT_OBJECTS - 1 },
    dwFailureCount{ 0 },
    events{},
    hThread{ &EventListener::SubEventListener::ListenForEvents, this }{
    events.emplace_back(hManager);
}

EventListener::SubEventListener::~SubEventListener(){
    // Indicate that the thread should terminate next time hManager is set
    terminate = true;

    // Set hManager, terminating the thread
    SetEvent(hManager);

    // Wait for the thread to finish
    hThread.join();
}

bool EventListener::SubEventListener::TrySubscribe(
    IN const HandleWrapper& hEvent,
    IN const std::vector<std::function<void()>>& callbacks
){
    // When reading or writing events, you must enter a critical section
    auto lock{ BeginCriticalSection(hSection) };

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
        SetEvent(hManager);

        auto status{ WaitForSingleObject(hManagerResponse, 1000) };

        // Ensure the manager event has been processed before making changes
        while(WAIT_OBJECT_0 != status){
            if(WAIT_TIMEOUT == status){
                // A loop of WaitForSingleObjects with a timeout of 1000 tends to be faster than
                // a single WaitForSingleObject with a timeout of INFINITE
                status = WaitForSingleObject(hManagerResponse, 1000);
            } else {
                // An error occured; return failure
                SetLastError(status);
                return false;
            }
        }

        events.emplace_back(hEvent);
        map.emplace(std::move(std::pair<HandleWrapper, std::vector<std::function<void()>>>{ hEvent, callbacks }));
        wrappers.emplace_back(hEvent);
        dwSlotsFree--;
        return true;
    }

    return false;
}

std::optional<std::vector<std::function<void()>>> EventListener::SubEventListener::GetSubscription(
    IN const HandleWrapper& hEvent
) const {
    // Enter a critical section before reading `map`
    auto lock{ BeginCriticalSection(hSection) };

    auto result{ map.find(hEvent) };
    if(result == map.end()){
        return std::nullopt;
    }

    return map.at(hEvent);
}

bool EventListener::SubEventListener::TryAddCallback(
    IN const HandleWrapper& hEvent,
    IN const std::function<void()>& callback
){
    // Enter a critical section before reading `map`
    auto lock{ BeginCriticalSection(hSection) };

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
LPVOID getAddress(std::function<void()> f){
    return *(f.template target<void(*)()>());
}

bool EventListener::SubEventListener::TryRemoveCallback(
    IN const HandleWrapper& hEvent,
    IN const std::function<void()>& callback
){
    // Enter a critical section before reading `map`
    auto lock{ BeginCriticalSection(hSection) };

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
    IN const HandleWrapper& hEvent
){
    auto lock{ BeginCriticalSection(hSection) };

    auto result{ map.find(hEvent) };
    if(result == map.end()){
        return false;
    }

    // Set hManager before modifying events, map, or dwSlotsFree
    SetEvent(hManager);

    auto status{ WaitForSingleObject(hManagerResponse, 1000) };

    // Ensure the manager event has been processed before making changes
    while(WAIT_OBJECT_0 != status){

        if(WAIT_ABANDONED_0 == status){
            // Manager response has gone stale
            hManagerResponse = CreateEventA(nullptr, false, false, nullptr);
        } else if(WAIT_TIMEOUT == status){
            status = WaitForSingleObject(hManagerResponse, 1000);
        } else {
            // An error occured; return failure
            return false;
        }
    }

    map.erase(hEvent);
    for(unsigned idx = 0; idx < events.size(); idx++){
        if(events[idx] == hEvent){
            events.erase(events.begin() + idx);
            idx--;
        }
    }
    for(unsigned idx = 0; idx < wrappers.size(); idx++){
        if(wrappers[idx] == hEvent){
            wrappers.erase(wrappers.begin() + idx);
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
    const HandleWrapper& hEvent,
    const std::vector<std::function<void()>>& callbacks
){
    // Acquire lock before accessing subeventlisteners
    auto lock{ BeginCriticalSection(hSection) };

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
    IN const HandleWrapper& hEvent
) const {
    // Acquire lock before accessing subeventlisteners
    auto lock{ BeginCriticalSection(hSection) };

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
    IN const HandleWrapper& hEvent,
    IN const std::function<void()>& callback
){
    // Acquire lock before accessing subeventlisteners
    auto lock{ BeginCriticalSection(hSection) };

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
    IN const HandleWrapper& hEvent,
    IN const std::function<void()>& callback
){
    // Acquire lock before accessing subeventlisteners
    auto lock{ BeginCriticalSection(hSection) };

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
    IN const HandleWrapper& hEvent
){
    // Acquire lock before accessing subeventlisteners
    auto lock{ BeginCriticalSection(hSection) };

    for(auto& sublistener : subeventlisteners){
        // See justification in EventListener::Subscribe
        if(sublistener->TryUnsubscribe(hEvent)){
            return true;
        }
    }

    LOG_ERROR("Unable to unsubscribe from event; Event may not have a subscription.");
    return false;
}