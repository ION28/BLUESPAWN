
#include "monitor/EventManager.h"

#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"

EventManager EventManager::manager;

EventManager::EventManager(){}

EventManager& EventManager::GetInstance(){
	return manager;
}

bool EventManager::SubscribeToEvent(const std::shared_ptr<Event>& e, const std::function<void()>& callback) {

	for(auto evt : vEventList){
		if(*evt == *e){
			evt->AddCallback(callback);
			return true;
		}
	} 

	std::shared_ptr<Event> evt = e;
	evt->AddCallback(callback);
	evt->Subscribe();

	vEventList.push_back(evt);

	return true;
}