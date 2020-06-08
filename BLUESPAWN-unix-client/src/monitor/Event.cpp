#include "monitor/Event.h"
#include "reaction/Log.h"
#include "util/eventlogs/EventLogs.h"
#include "monitor/EventListener.h"
#include "user/bluespawn.h"

Event::Event(EventType type) : type(type) {}

void Event::AddCallback(const std::function<void()>& callback) {
	callbacks.push_back(callback);
}

std::string wsCallbackExceptionMessage{ "Error occured while executing a callback for a monitor event" };

void RunCallback(const HuntEnd& callback){
	/*__try{
		callback();
	} __except(EXCEPTION_EXECUTE_HANDLER){
		Bluespawn::io.InformUser(wsCallbackExceptionMessage, ImportanceLevel::HIGH);
	}*/
	callback();
}

void Event::RunCallbacks() const {
	for(auto& callback : callbacks){
		RunCallback(callback);
	}
}

/************************
***   EventLogEvent   ***
*************************/
//TODO: Linuxize this
/*
EventLogEvent::EventLogEvent(const std::string& channel, int eventID, const std::vector<EventLogs::XpathQuery>& queries) :
	Event(EventType::EventLog), 
    channel(channel), 
	eventID(eventID), 
	eventLogTrigger{ [this](EventLogs::EventLogItem){ this->RunCallbacks(); } } {}

bool EventLogEvent::Subscribe(){
	LOG_VERBOSE(1, "Subscribing to EventLog " << channel << " for Event ID " << eventID);
	unsigned int status{};
	auto subscription = EventLogs::SubscribeToEvent(GetChannel(), GetEventID(), eventLogTrigger, queries);
	if(subscription){
		eventSub = *subscription;
	}
	return status;
}

std::string EventLogEvent::GetChannel() const {
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

FileEvent::FileEvent(const FileSystem::Folder& directory) :
	Event(EventType::FileSystem),
	directory{ directory },
	hEvent{ nullptr }{}

bool FileEvent::Subscribe(){
	LOG_VERBOSE(1, "Subscribing to File " << directory.GetFolderPath());

	auto& manager{ EventListener::GetInstance() };

	hEvent = GenericWrapper<HANDLE>{ FindFirstChangeNotificationW(directory.GetFolderPath().c_str(), false, 0x17F), FindCloseChangeNotification };
	if(!hEvent){
		LOG_ERROR("Failed to resubscribe to changes to " << directory.GetFolderPath() << " (Error " << errno << ")");
		return false;
	}

	// Make local copies to be captured in the lambda
	auto hEvent{ this->hEvent };
	auto directory{ this->directory };

	auto subscription = manager.Subscribe(hEvent, {
		[directory, hEvent](){
			auto status{ FindNextChangeNotification(hEvent) };
			if(!status){
				LOG_ERROR("Failed to resubscribe to changes to " << directory.GetFolderPath() << " (Error " << errno << ")");
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
	std::vector<std::shared_ptr<Event>> GetRegistryEvents(HKEY hkHive, const std::string& path, bool WatchWow64, bool WatchUsers, bool WatchSubkeys){
		auto& base = std::make_shared<RegistryEvent>(RegistryKey{ hkHive, path }, WatchSubkeys);
		std::unordered_set<std::shared_ptr<Event>> vKeys{};
		if(base->GetKey().Exists()){
			vKeys.emplace(base);
		}
		if(WatchWow64){
			std::shared_ptr<RegistryEvent> Wow64Key{ std::make_shared<RegistryEvent>(RegistryKey{ HKEY(hkHive), path, true }, WatchSubkeys) };
			if(Wow64Key->GetKey().Exists() && Wow64Key->GetKey().GetName().find("WOW6432Node") != std::string::npos){
				vKeys.emplace(std::static_pointer_cast<Event>(Wow64Key));
			}
		}
		if(WatchUsers){
			std::vector<RegistryKey> hkUserHives{ RegistryKey{HKEY_USERS}.EnumerateSubkeys() };
			for(auto& hive : hkUserHives){
				std::shared_ptr<RegistryEvent> key{ std::make_shared<RegistryEvent>(RegistryKey{ HKEY(hive), path, false }, WatchSubkeys) };
				if(key->GetKey().Exists()){
					vKeys.emplace(std::static_pointer_cast<Event>(key));
				}
				if(WatchWow64){
					std::shared_ptr<RegistryEvent> Wow64Key{ std::make_shared<RegistryEvent>(RegistryKey{ HKEY(hive), path, true }, WatchSubkeys) };
					if(Wow64Key->GetKey().Exists() && Wow64Key->GetKey().GetName().find("WOW6432Node") != std::string::npos){
						vKeys.emplace(std::static_pointer_cast<Event>(Wow64Key));
					}
				}
			}
		}
		return { vKeys.begin(), vKeys.end() };
	}
}
*/