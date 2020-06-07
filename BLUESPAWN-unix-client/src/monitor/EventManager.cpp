#include "monitor/EventManager.h"

#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"

EventManager EventManager::manager;

EventManager::EventManager(){}

EventManager& EventManager::GetInstance(){
	return manager;
}

unsigned int EventManager::SubscribeToEvent(const std::shared_ptr<Event>& e, const std::function<void()>& callback) {
	unsigned int status = ERROR_SUCCESS;

	for(auto evt : vEventList){
		if(*evt == *e){
			evt->AddCallback(callback);
			return status;
		}
	} 

	std::shared_ptr<Event> evt = e;
	evt->AddCallback(callback);
	evt->Subscribe();

	vEventList.push_back(evt);

	return status;
}