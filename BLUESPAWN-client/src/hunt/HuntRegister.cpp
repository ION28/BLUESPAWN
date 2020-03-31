#include "hunt/HuntRegister.h"
#include <iostream>
#include <functional>
#include "monitor/EventManager.h"
#include "util/log/Log.h"

#include "common/Utils.h"

HuntRegister::HuntRegister(const IOBase& io) : io(io) {}

void HuntRegister::RegisterHunt(std::shared_ptr<Hunt> hunt) {
	vRegisteredHunts.emplace_back(hunt);
}

std::vector<std::shared_ptr<DETECTION>> HuntRegister::RunHunts(DWORD dwTactics, DWORD dwDataSource, DWORD dwAffectedThings, const Scope& scope){
	io.InformUser(L"Starting a hunt for " + std::to_wstring(vRegisteredHunts.size()) + L" techniques.");

	std::vector<std::shared_ptr<DETECTION>> detections{};
	for(auto name : vRegisteredHunts) {
		ADD_ALL_VECTOR(detections, name->RunHunt(scope));
	}
	io.InformUser(L"Successfully ran " + std::to_wstring(vRegisteredHunts.size()) + L" hunts.");

	return detections;
}

std::vector<std::shared_ptr<DETECTION>> HuntRegister::RunHunt(Hunt& hunt, const Scope& scope){
	io.InformUser(L"Starting scan for " + hunt.GetName());
	int huntRunStatus = 0;

	std::vector<std::shared_ptr<DETECTION>> detections{ hunt.RunHunt(scope) };

	io.InformUser(L"Successfully scanned for " + hunt.GetName());

	return detections;
}

void HuntRegister::SetupMonitoring() {
	auto& EvtManager = EventManager::GetInstance();
	for (auto name : vRegisteredHunts) {
		io.InformUser(L"Setting up monitoring for " + name->GetName());
			for(auto event : name->GetMonitoringEvents()) {
				std::function<void()> callback{ std::bind(&Hunt::RunHunt, name.get(), Scope{}) };
				DWORD status = EvtManager.SubscribeToEvent(event, callback);
				if(status != ERROR_SUCCESS){
					LOG_ERROR(L"Monitoring for " << name->GetName() << L" failed with error code " << status);
				}
		}
	}
}