#include "monitor/Event.h"
#include "hunt/reaction/Log.h"
#include "util/eventlogs/EventLogs.h"

Event::Event(EventType type) : type(type) {}

void Event::AddCallback(const std::function<void()>& callback) {
	callbacks.push_back(callback);
}

void Event::RunCallbacks() const {
	for(auto callback : callbacks){
		callback();
	}
}

/************************
***   EventLogEvent   ***
*************************/
EventLogEvent::EventLogEvent(const std::wstring& channel, int eventID) : 
	Event(EventType::EventLog), 
    channel(channel), 
	eventID(eventID), 
	eventLogTrigger{ [this](EventLogs::EventLogItem){ this->RunCallbacks(); } } {}

bool EventLogEvent::Subscribe(){
	DWORD status{};
	auto subscription = EventLogs::SubscribeToEvent(const_cast<LPWSTR>(GetChannel().c_str()), GetEventID(), eventLogTrigger, &status);
	if(subscription){
		eventSub = *subscription;
	}
	return status;
}

std::wstring EventLogEvent::GetChannel() const {
	return channel;
}

int EventLogEvent::GetEventID() const {
	return eventID;
}

bool EventLogEvent::operator==(const Event& e) const {
	if(e.type == EventType::EventLog && dynamic_cast<const EventLogEvent*>(&e)){
		auto evt = dynamic_cast<const EventLogEvent*>(&e);
		return evt->GetChannel() == channel && evt->GetEventID() == eventID;
	} else return false;
}

void RegistryEvent::DispatchRegistryThread(){
	std::optional<HandleWrapper> hEvents[MAXIMUM_WAIT_OBJECTS] = {};
	std::optional<RegistryEvent> RegistryEvents[MAXIMUM_WAIT_OBJECTS - 1] = {};
	RegistryEvent::hListener = hEvents[0] = CreateEventW(nullptr, false, false, nullptr);
	hEvents[1] = RegistryEvent::subscribe->GetEvent();
	RegistryEvents[0] = *RegistryEvent::subscribe;
	RegistryEvent::subscribe = std::nullopt;
	RegistryEventThreadArgs ThreadArgs = { &hEvents, &RegistryEvents };
	HandleWrapper thread = CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(RegistryEvent::RegistryEventThreadFunction), &ThreadArgs, 0, nullptr);
	WaitForSingleObject(RegistryEvent::hSubscribed, INFINITE);
}

void RegistryEvent::RegistryEventThreadFunction(RegistryEventThreadArgs* arguments){
	RegistryEventThreadArgs args = *arguments;
	SetEvent(RegistryEvent::hSubscribed);
	int errors = 0;
	while(true){
		int count = 0;
		while(count < MAXIMUM_WAIT_OBJECTS){
			if(args.WaitObjects[count]){
				count++;
			}
		}

		if(count <= 1){
			if(args.WaitObjects[0] && hListener == args.WaitObjects[0]->Get()){
				hListener = std::nullopt;
			}

			return;
		}

		HANDLE* handles = new HANDLE[count];
		int index = 0;
		for(int i = 0; i < count; i++){
			if(args.WaitObjects[i]){
				handles[index] = *args.WaitObjects[i];
				if(i != index){
					args.WaitObjects[index] = *args.WaitObjects[i];
					args.WaitObjects[i] = std::nullopt;
					args.Events[index - 1] = *args.Events[i - 1];
					args.Events[i - 1] = std::nullopt;
				}
				index++;
			}
		}
		
		auto result = WaitForMultipleObjects(count, handles, false, INFINITE);
		if(result == WAIT_OBJECT_0){
			if(RegistryEvent::subscribe){
				if(count == MAXIMUM_WAIT_OBJECTS){
					DispatchRegistryThread();
				} else {
					args.WaitObjects[count] = RegistryEvent::subscribe->GetEvent();
					args.Events[count - 1] = *RegistryEvent::subscribe;
					RegistryEvent::subscribe = std::nullopt;
					SetEvent(RegistryEvent::hSubscribed);
				}
			}
			errors = 0;
		} else if(result > WAIT_OBJECT_0 && result < WAIT_OBJECT_0 + MAXIMUM_WAIT_OBJECTS) {
			auto index = result - WAIT_OBJECT_0;

			if(args.Events[index - 1]){
				args.Events[index - 1]->RunCallbacks();
			}
			errors = 0;
		} else if(result > WAIT_ABANDONED_0 && result < WAIT_ABANDONED_0 + MAXIMUM_WAIT_OBJECTS) {
			LOG_WARNING("A registry event appears to have been abandoned");
			auto index = result - WAIT_ABANDONED_0;
			args.Events[index - 1] = std::nullopt;
			args.WaitObjects[index] = std::nullopt;
			errors = 0;
		} else {
			errors += 1;
			LOG_ERROR("Error " << result << " occured in the registry monitor function");
			if(errors > 5){
				LOG_ERROR(5 << " consecutive errors occured in the registry monitor function; exiting (" << count << " monitor events discarded)");
				return;
			}
		}
	}
}

RegistryEvent::RegistryEvent(const Registry::RegistryKey& key, bool WatchSubkeys) :
	Event(EventType::Registry),
	key{ key },
	WatchSubkeys{ WatchSubkeys },
	hEvent{ CreateEventW(nullptr, false, false, nullptr) }{}

bool RegistryEvent::Subscribe(){
	auto status = RegNotifyChangeKeyValue(key, WatchSubkeys, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC, hEvent, true);
	if(status == ERROR_SUCCESS){
		status = WaitForSingleObject(RegistryEvent::hMutex, INFINITE);
		if(status == STATUS_WAIT_0){
			RegistryEvent::subscribe = *this;
			if(RegistryEvent::hListener){
				SetEvent(*RegistryEvent::hListener);
				WaitForSingleObject(RegistryEvent::hEvent, INFINITE);
			} else {
				DispatchRegistryThread();
			}
			ReleaseMutex(RegistryEvent::hMutex);
		}
	}
	return status == ERROR_SUCCESS;
}

bool RegistryEvent::operator==(const Event& e) const {
	if(e.type == EventType::Registry && dynamic_cast<const RegistryEvent*>(&e)){
		auto evt = dynamic_cast<const RegistryEvent*>(&e);
		return evt->key == key && evt->WatchSubkeys == WatchSubkeys;
	} else return false;
}

const HandleWrapper& RegistryEvent::GetEvent() const {
	return hEvent;
}