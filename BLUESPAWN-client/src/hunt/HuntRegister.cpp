#include "hunt/HuntRegister.h"
#include <iostream>
#include <functional>
#include "monitor/EventManager.h"
#include "util/log/Log.h"

HuntRegister::HuntRegister(const IOBase& io) : io(io) {}

void HuntRegister::RegisterHunt(std::shared_ptr<Hunt> hunt) {
	// The actual hunt itself is stored in the vector here!
	// Make sure that all internal references to it are referencing
	// the copy in vRegisteredHunts and not the argument to this function.
	vRegisteredHunts.emplace_back(hunt);

	/*for(DWORD i = 1; i != 0; i <<= 1){
		if(hunt->UsesTactics(i)){
			mTactics[(Tactic::Tactic) i].emplace_back(hunt);
		}

		if(hunt->UsesSources(i)){
			mDataSources[(DataSource::DataSource) i].emplace_back(hunt);
		}

		if(hunt->AffectsStuff(i)){
			mAffectedThings[(AffectedThing::AffectedThing) i].emplace_back(hunt);
		}
	}*/
}

void HuntRegister::RunHunts(DWORD dwTactics, DWORD dwDataSource, DWORD dwAffectedThings, const Scope& scope, Aggressiveness aggressiveness, const Reaction& reaction){
	io.InformUser(L"Starting a hunt for " + std::to_wstring(vRegisteredHunts.size()) + L" techniques.");
	int huntsRan = 0;

  for (auto name : vRegisteredHunts) {
		int huntRunStatus = 0;
		auto level = getLevelForHunt(*name, aggressiveness);
		switch (level) {
			case Aggressiveness::Intensive:
				huntRunStatus = name->ScanIntensive(scope, reaction);
				break;
			case Aggressiveness::Normal:
				huntRunStatus = name->ScanNormal(scope, reaction);
				break;
			case Aggressiveness::Cursory:
				huntRunStatus = name->ScanCursory(scope, reaction);
				break;
		}
		
		if (huntRunStatus != -1) {
			++huntsRan;
		}
	}
	if (huntsRan != vRegisteredHunts.size()) {
		io.InformUser(L"Successfully ran " + std::to_wstring(huntsRan) + L" hunts. There were no scans available for " + std::to_wstring(vRegisteredHunts.size() - huntsRan) + L" of the techniques.");
	}
	else {
		io.InformUser(L"Successfully ran " + std::to_wstring(huntsRan) + L" hunts.");
	}
}

void HuntRegister::RunHunt(Hunt& hunt, const Scope& scope, Aggressiveness aggressiveness, const Reaction& reaction){
	io.InformUser(L"Starting scan for " + hunt.GetName());
	int huntRunStatus = 0;

	auto level = getLevelForHunt(hunt, aggressiveness);
	switch (level) {
		case Aggressiveness::Intensive:
			huntRunStatus = hunt.ScanIntensive(scope, reaction);
			break;
		case Aggressiveness::Normal:
			huntRunStatus = hunt.ScanNormal(scope, reaction);
			break;
		case Aggressiveness::Cursory:
			huntRunStatus = hunt.ScanCursory(scope, reaction);
			break;
	}

	if (huntRunStatus == -1) {
		io.InformUser(L"No scans for this level available for " + hunt.GetName());
	}
	else {
		io.InformUser(L"Successfully scanned for " + hunt.GetName());
	}
}

void HuntRegister::SetupMonitoring(Aggressiveness aggressiveness, const Reaction& reaction) {
	auto& EvtManager = EventManager::GetInstance();
	for (auto name : vRegisteredHunts) {
		auto level = getLevelForHunt(*name, aggressiveness);
		if(name->SupportsScan(level)) {
			io.InformUser(L"Setting up monitoring for " + name->GetName());
			for(auto event : name->GetMonitoringEvents()) {

				std::function<void()> callback;

				switch(level) {
				case Aggressiveness::Intensive:
					callback = std::bind(&Hunt::ScanIntensive, name.get(), Scope{}, reaction);
					break;
				case Aggressiveness::Normal:
					callback = std::bind(&Hunt::ScanNormal, name.get(), Scope{}, reaction);
					break;
				case Aggressiveness::Cursory:
					callback = std::bind(&Hunt::ScanCursory, name.get(), Scope{}, reaction);
					break;
				}

				if(name->SupportsScan(level)) {
					DWORD status = EvtManager.SubscribeToEvent(event, callback);
					if(status != ERROR_SUCCESS){
						LOG_ERROR(L"Monitoring for " << name->GetName() << L" failed with error code " << status);
					}
				}
			}
		}
	}
}

Aggressiveness HuntRegister::getLevelForHunt(Hunt& hunt, Aggressiveness aggressiveness) {
	if (aggressiveness == Aggressiveness::Intensive) {
		if (hunt.SupportsScan(Aggressiveness::Intensive)) 
			return Aggressiveness::Intensive;
		else if (hunt.SupportsScan(Aggressiveness::Normal)) 
			return Aggressiveness::Normal;
	}
	else if (aggressiveness == Aggressiveness::Normal) 
		if (hunt.SupportsScan(Aggressiveness::Normal)) 
			return Aggressiveness::Normal;

	return Aggressiveness::Cursory;
}