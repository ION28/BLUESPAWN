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
EventLogEvent::EventLogEvent(const std::wstring& channel, int eventID, const std::vector<EventLogs::XpathQuery>& queries) :
	Event(EventType::EventLog), 
    channel(channel), 
	eventID(eventID), 
	eventLogTrigger{ [this](EventLogs::EventLogItem){ this->RunCallbacks(); } } {}

bool EventLogEvent::Subscribe(){
	LOG_VERBOSE(1, L"Subscribing to EventLog " << channel << L" for Event ID " << eventID);
	DWORD status{};
	auto subscription = EventLogs::SubscribeToEvent(GetChannel(), GetEventID(), eventLogTrigger, queries);
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

std::vector<EventLogs::XpathQuery> EventLogEvent::GetQueries() const {
	return this->queries;
}

bool EventLogEvent::operator==(const Event& e) const {
	if(e.type == EventType::EventLog && dynamic_cast<const EventLogEvent*>(&e)){
		auto evt = dynamic_cast<const EventLogEvent*>(&e);
		return evt->GetChannel() == channel && evt->GetEventID() == eventID;
	} else return false;
}

/************************
***   RegistryEvent   ***
*************************/
void RegistryEvent::DispatchRegistryThread(){
	std::optional<RegistryEvent>* RegistryEvents = new std::optional<RegistryEvent>[MAXIMUM_WAIT_OBJECTS - 1]{};
	RegistryEvent::hListener = CreateEventW(nullptr, false, false, nullptr);
	RegistryEvents[0] = *RegistryEvent::subscribe;
	RegistryEvent::subscribe = std::nullopt;
	RegistryEventThreadArgs ThreadArgs = { *RegistryEvent::hListener, RegistryEvents };
	HandleWrapper thread = CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(RegistryEvent::RegistryEventThreadFunction), &ThreadArgs, 0, nullptr);
	WaitForSingleObject(RegistryEvent::hSubscribed, INFINITE);
}

void RegistryEvent::RegistryEventThreadFunction(RegistryEventThreadArgs* arguments){
	RegistryEventThreadArgs args = *arguments;
	SetEvent(RegistryEvent::hSubscribed);
	int errors = 0;
	while(true){
		int count = args.Notify ? 1 : 0;
		int idx = 0;
		while(idx < MAXIMUM_WAIT_OBJECTS){
			if(args.Events[idx++]){
				count++;
			}
		}

		if(count <= 1){
			if(args.Notify && hListener == args.Notify){
				hListener = std::nullopt;
			}
			delete[] args.Events;
			return;
		}

		HANDLE* handles = new HANDLE[count];
		int index = 0;
		if(args.Notify){
			handles[index++] = args.Notify;
		}
		int valid_idx = 0;
		for(int i = 0; i < count; i++){
			if(args.Events[i]){
				handles[index++] = args.Events[i]->GetEvent();
				if(i != valid_idx){
					args.Events[valid_idx] = *args.Events[i];
					args.Events[i] = std::nullopt;
				}
				valid_idx++;
			}
		}
		
		auto result = WaitForMultipleObjects(count, handles, false, INFINITE);
		if(result == WAIT_OBJECT_0){
			if(RegistryEvent::subscribe){
				if(count == MAXIMUM_WAIT_OBJECTS){
					DispatchRegistryThread();
				} else {
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
				if(ERROR_SUCCESS != RegNotifyChangeKeyValue(args.Events[index - 1]->key, args.Events[index - 1]->WatchSubkeys,
					REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC, args.Events[index - 1]->hEvent, true)){
					LOG_ERROR("Unable to reset listener on key " << args.Events[index - 1]->key << ". Unable to continue to monitor changes to this key.");
					args.Events[index - 1] = std::nullopt;
				}
			}
			errors = 0;
		} else if(result == WAIT_ABANDONED_0){
			args.Notify = INVALID_HANDLE_VALUE;
		} else if(result > WAIT_ABANDONED_0 && result < WAIT_ABANDONED_0 + MAXIMUM_WAIT_OBJECTS) {
			LOG_WARNING("Registry listener on " << args.Events[index - 1]->key << " appears to have been abandoned");
			auto index = result - WAIT_ABANDONED_0;
			args.Events[index - 1] = std::nullopt;
			errors = 0;
		} else {
			errors += 1;
			LOG_ERROR("Error " << GetLastError() << " occured in the registry monitor function");
			if(errors > 5){
				LOG_ERROR(5 << " consecutive errors occured in the registry monitor function; exiting (" << count << " monitor events discarded)");
				return;
			}
		}
	}
}

HandleWrapper RegistryEvent::hMutex = CreateMutexW(nullptr, false, nullptr);
HandleWrapper RegistryEvent::hSubscribed = CreateEventW(nullptr, false, false, nullptr);
std::optional<HandleWrapper> RegistryEvent::hListener = std::nullopt;
std::optional<RegistryEvent> RegistryEvent::subscribe = std::nullopt;

RegistryEvent::RegistryEvent(const Registry::RegistryKey& key, bool WatchSubkeys) :
	Event(EventType::Registry),
	key{ key },
	WatchSubkeys{ WatchSubkeys },
	hEvent{ CreateEventW(nullptr, false, false, nullptr) }{}

bool RegistryEvent::Subscribe(){
	LOG_VERBOSE(1, L"Subscribing to Registry Key " << key.ToString());
	auto status = RegNotifyChangeKeyValue(key, WatchSubkeys, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC, hEvent, true);
	if(status == ERROR_SUCCESS){
		status = WaitForSingleObject(RegistryEvent::hMutex, INFINITE);
		if(status == STATUS_WAIT_0){
			RegistryEvent::subscribe = *this;
			if(RegistryEvent::hListener){
				SetEvent(*RegistryEvent::hListener);
				WaitForSingleObject(RegistryEvent::hSubscribed, INFINITE);
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

namespace Registry {
	std::vector<std::shared_ptr<Event>> GetRegistryEvents(HKEY hkHive, const std::wstring& path, bool WatchWow64, bool WatchUsers, bool WatchSubkeys){
		std::unordered_set<std::shared_ptr<Event>> vKeys{ { std::static_pointer_cast<Event>(std::make_shared<RegistryEvent>(RegistryKey{ hkHive, path })) } };
		if(WatchWow64){
			std::shared_ptr<RegistryEvent> Wow64Key{ std::make_shared<RegistryEvent>(RegistryKey{ HKEY(hkHive), path, true }) };
			if(Wow64Key->key.Exists()){
				vKeys.emplace(std::static_pointer_cast<Event>(Wow64Key));
			}
		}
		if(WatchUsers){
			std::vector<RegistryKey> hkUserHives{ RegistryKey{HKEY_USERS}.EnumerateSubkeys() };
			for(auto& hive : hkUserHives){
				std::shared_ptr<RegistryEvent> key{ std::make_shared<RegistryEvent>(RegistryKey{ HKEY(hive), path, false }) };
				if(key->key.Exists()){
					vKeys.emplace(std::static_pointer_cast<Event>(key));
				}
				if(WatchWow64){
					std::shared_ptr<RegistryEvent> Wow64Key{ std::make_shared<RegistryEvent>(RegistryKey{ HKEY(hive), path, true }) };
					if(Wow64Key->key.Exists()){
						vKeys.emplace(std::static_pointer_cast<Event>(Wow64Key));
					}
				}
			}
		}
		return { vKeys.begin(), vKeys.end() };
	}
}