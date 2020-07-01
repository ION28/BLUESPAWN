#include "monitor/EventManager.h"

#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"

EventManager EventManager::manager;

EventManager::EventManager(){}

EventManager& EventManager::GetInstance(){
	return manager;
}

DWORD EventManager::SubscribeToEvent(std::unique_ptr<Event>&& e, const std::function<void()>& callback) {
	DWORD status = ERROR_SUCCESS;

	for(auto& evt : vEventList){
		if(*evt == *e){
			evt->AddCallback(callback);
			return status;
		}
	} 

	e->AddCallback(callback);
	e->Subscribe();

	vEventList.push_back(std::move(e));

	return status;
}