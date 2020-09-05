#include "monitor/Event.h"
#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"
#include "monitor/EventListener.h"
#include "user/bluespawn.h"

Event::Event(EventType type) : type(type) {}

void Event::AddCallback(const std::function<void(IN CONST Scope&)>& callback, IN CONST Scope& scope) {
	callbacks.push_back(std::make_pair(callback, scope));
}

void Event::RunCallbacks() const {
	for(auto pair : callbacks){
		pair.first(pair.second);
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

	auto keypath{ key.GetName() };
	auto status{ RegNotifyChangeKeyValue(key, WatchSubkeys, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC, hEvent, true) };
	if(ERROR_SUCCESS != status){
		LOG_ERROR("Failed to subscribe to changes to " << key << " (Error " << status << ")");
		return false;
	}

	// Make class members locals so they can be captured
	auto key{ this->key };
	auto WatchSubkeys{ this->WatchSubkeys };
	auto hEvent{ this->hEvent };

	auto subscription = manager.Subscribe(hEvent, {
		[key, WatchSubkeys, hEvent](){
			auto status{ RegNotifyChangeKeyValue(key, WatchSubkeys, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC, hEvent, true) };
			auto name{ key.GetName() };
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

	return true;
}

bool RegistryEvent::operator==(const Event& e) const {
	if(e.type == EventType::Registry && dynamic_cast<const RegistryEvent*>(&e)){
		auto evt = dynamic_cast<const RegistryEvent*>(&e);
		return evt->key.GetName() == key.GetName() && evt->WatchSubkeys == WatchSubkeys;
	} else return false;
}

const HandleWrapper& RegistryEvent::GetEvent() const {
	return hEvent;
}

const Registry::RegistryKey& RegistryEvent::GetKey() const{
	return key;
}

FileEvent::FileEvent(const FileSystem::Folder& directory) :
	Event(EventType::FileSystem),
	directory{ directory },
	hEvent{ nullptr }{}

bool FileEvent::Subscribe(){
	LOG_VERBOSE(1, L"Subscribing to File " << directory.GetFolderPath());

	auto& manager{ EventListener::GetInstance() };

	hEvent = GenericWrapper<HANDLE>{ FindFirstChangeNotificationW(directory.GetFolderPath().c_str(), false, 0x17F), FindCloseChangeNotification };
	if(!hEvent){
		LOG_ERROR("Failed to resubscribe to changes to " << directory.GetFolderPath() << " (Error " << GetLastError() << ")");
		return false;
	}

	// Make local copies to be captured in the lambda
	auto hEvent{ this->hEvent };
	auto directory{ this->directory };

	auto subscription = manager.Subscribe(hEvent, {
		[directory, hEvent](){
			auto status{ FindNextChangeNotification(hEvent) };
			if(!status){
				LOG_ERROR("Failed to resubscribe to changes to " << directory.GetFolderPath() << " (Error " << GetLastError() << ")");
			}
		},
		std::bind(&FileEvent::RunCallbacks, this)
	});
	if(!subscription){
		LOG_ERROR("Failed to register subscription for changes to " << directory.GetFolderPath());
		return false;
	}

	return true;
}

bool FileEvent::operator==(const Event& e) const {
	if(e.type == EventType::FileSystem && dynamic_cast<const FileEvent*>(&e)){
		auto evt = dynamic_cast<const FileEvent*>(&e);
		return evt->GetFolder().GetFolderPath() == directory.GetFolderPath();
	} else return false;
}

const GenericWrapper<HANDLE>& FileEvent::GetEvent() const {
	return hEvent;
}

const FileSystem::Folder& FileEvent::GetFolder() const {
	return directory;
}

namespace Registry {
	void GetRegistryEvents(OUT std::vector<std::pair<std::unique_ptr<Event>, Scope>>& dest, IN CONST Scope& scope,
						   IN HKEY hkHive, IN CONST std::wstring& path, IN bool WatchWow64 OPTIONAL, 
						   IN bool WatchUsers OPTIONAL, IN bool WatchSubkeys OPTIONAL){
		std::unordered_set<RegistryKey> vKeys{ RegistryKey{ hkHive, path } };
		if(WatchWow64){
			RegistryKey Wow64Key{ HKEY(hkHive), path, true };
			if(Wow64Key.Exists()){
				vKeys.emplace(Wow64Key);
			}
		}
		if(WatchUsers){
			auto hkUserHives{ RegistryKey{ HKEY_USERS }.EnumerateSubkeys() };
			for(auto& hive : hkUserHives){
				RegistryKey key{ HKEY(hive), path, false };
				if(key.Exists()){
					vKeys.emplace(key);
				}
				if(WatchWow64){
					RegistryKey Wow64Key{ HKEY(hive), path, true };
					if(Wow64Key.Exists()){
						vKeys.emplace(Wow64Key);
					}
				}
			}
		}
		
		for(auto& key : vKeys){
			dest.emplace_back(std::make_pair(std::make_unique<RegistryEvent>(key), scope));
		}
	}
}
