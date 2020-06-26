#include "hunt/HuntRegister.h"
#include <iostream>
#include <functional>
#include "monitor/EventManager.h"
#include "util/log/Log.h"
#include "user/bluespawn.h"
#include "common/Utils.h"
#include "common/ThreadPool.h"
#include "common/Promise.h"

void HuntRegister::RegisterHunt(std::unique_ptr<Hunt>&& hunt) {
	vRegisteredHunts.emplace_back(std::move(hunt));
}

std::vector<Promise<std::vector<std::reference_wrapper<Detection>>>>
HuntRegister::RunHunts(IN CONST Scope& scope OPTIONAL, IN CONST bool async OPTIONAL){
	Bluespawn::io.InformUser(L"Starting a hunt for " + std::to_wstring(vRegisteredHunts.size()) + L" techniques.");

	std::vector<Promise<std::vector<std::reference_wrapper<Detection>>>> detections{};
	for(auto& name : vRegisteredHunts) {
		detections.emplace_back(RunHunt(*name, scope));
	}

	if(async){
		std::vector<HANDLE> handles(detections.begin(), detections.end());

		for(size_t idx{ 0 }; idx < handles.size(); idx += MAXIMUM_WAIT_OBJECTS){
			auto count{ min(handles.size() - idx, MAXIMUM_WAIT_OBJECTS) };
			auto result{ WaitForMultipleObjects(count, handles.data() + idx, true, INFINITE) };
			if(result != WAIT_OBJECT_0){
				LOG_ERROR("Failed to wait for hunts to finish (status 0x" << std::hex << result << ", error " <<
						  std::hex << GetLastError() << ")");
				throw std::exception("Failed to wait for hunts to finish!");
			}
		}

		auto successes{ std::count_if(detections.begin(), detections.end(), 
									  [](auto result){ return result.Fufilled(); }) };

		Bluespawn::io.InformUser(L"Successfully ran " + std::to_wstring(successes) + L" hunts.");
	}
	
	return detections;
}

Promise<std::vector<std::reference_wrapper<Detection>>> HuntRegister::RunHunt(IN Hunt& hunt, 
																			  IN CONST Scope& scope OPTIONAL){
	Bluespawn::io.InformUser(L"Starting scan for " + hunt.GetName());

	return ThreadPool::GetInstance().RequestPromise<std::vector<std::reference_wrapper<Detection>>>(
		std::bind(&Hunt::RunHunt, hunt, scope));
}

void HuntRegister::SetupMonitoring(){
	auto& EvtManager{ EventManager::GetInstance() };
	for (auto& name : vRegisteredHunts) {
		Bluespawn::io.InformUser(L"Setting up monitoring for " + name->GetName());
		for(auto& event : name->GetMonitoringEvents()) {
			std::function<void()> callback{ std::bind(&Hunt::RunHunt, name.get(), Scope{}) };
			DWORD status{ EvtManager.SubscribeToEvent(std::move(event), callback) };
			if(status != ERROR_SUCCESS){
				LOG_ERROR(L"Monitoring for " << name->GetName() << L" failed with error code " << status);
			}
		}
	}
}
