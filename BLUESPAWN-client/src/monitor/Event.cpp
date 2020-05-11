#include "monitor/Event.h"
#include "reaction/Log.h"
#include "util/eventlogs/EventLogs.h"
#include "monitor/EventListener.h"

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

RegistryEvent::RegistryEvent(const Registry::RegistryKey& key, bool WatchSubkeys) :
	Event(EventType::Registry),
	key{ key },
	WatchSubkeys{ WatchSubkeys },
	hEvent{ CreateEventW(nullptr, false, false, nullptr) }{}

bool RegistryEvent::Subscribe(){
	LOG_VERBOSE(1, L"Subscribing to Registry Key " << key.ToString());
	auto& manager{ EventListener::GetInstance() };
	auto subscription = manager.Subscribe(hEvent, {
		[this](){
			auto status{ RegNotifyChangeKeyValue(key, WatchSubkeys, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC, hEvent, true) };
			if(ERROR_SUCCESS != status){
				LOG_ERROR("Failed to resubscribe to changes to " << key << " (Error " << status << ")");
			}
		},
		std::bind(&RegistryEvent::RunCallbacks, this)
    });

	if(!subscription){
		LOG_ERROR("Failed to register subscription for changes to " << key);
		return false;
	}

	auto status{ RegNotifyChangeKeyValue(key, WatchSubkeys, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC, hEvent, true) };
	if(ERROR_SUCCESS != status){
		LOG_ERROR("Failed to subscribe to changes to " << key << " (Error " << status << ")");
		return false;
	}

	return true;
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

const Registry::RegistryKey& RegistryEvent::GetKey() const{
	return key;
}

namespace Registry {
	std::vector<std::shared_ptr<Event>> GetRegistryEvents(HKEY hkHive, const std::wstring& path, bool WatchWow64, bool WatchUsers, bool WatchSubkeys){
		std::unordered_set<std::shared_ptr<Event>> vKeys{ { std::static_pointer_cast<Event>(std::make_shared<RegistryEvent>(RegistryKey{ hkHive, path })) } };
		if(WatchWow64){
			std::shared_ptr<RegistryEvent> Wow64Key{ std::make_shared<RegistryEvent>(RegistryKey{ HKEY(hkHive), path, true }) };
			if(Wow64Key->GetKey().Exists()){
				vKeys.emplace(std::static_pointer_cast<Event>(Wow64Key));
			}
		}
		if(WatchUsers){
			std::vector<RegistryKey> hkUserHives{ RegistryKey{HKEY_USERS}.EnumerateSubkeys() };
			for(auto& hive : hkUserHives){
				std::shared_ptr<RegistryEvent> key{ std::make_shared<RegistryEvent>(RegistryKey{ HKEY(hive), path, false }) };
				if(key->GetKey().Exists()){
					vKeys.emplace(std::static_pointer_cast<Event>(key));
				}
				if(WatchWow64){
					std::shared_ptr<RegistryEvent> Wow64Key{ std::make_shared<RegistryEvent>(RegistryKey{ HKEY(hive), path, true }) };
					if(Wow64Key->GetKey().Exists()){
						vKeys.emplace(std::static_pointer_cast<Event>(Wow64Key));
					}
				}
			}
		}
		return { vKeys.begin(), vKeys.end() };
	}
}