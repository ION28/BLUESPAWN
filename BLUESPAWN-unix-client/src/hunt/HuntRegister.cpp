#include "hunt/HuntRegister.h"
#include <iostream>
#include <functional>
#include "monitor/EventManager.h"
#include "util/log/Log.h"
#include "common/StringUtils.h"
#include "user/bluespawn.h"

HuntRegister::HuntRegister(const IOBase& io) : io(io) {}

void HuntRegister::RegisterHunt(std::shared_ptr<Hunt> hunt) {
	// The actual hunt itself is stored in the vector here!
	// Make sure that all internal references to it are referencing
	// the copy in vRegisteredHunts and not the argument to this function.
	vRegisteredHunts.emplace_back(hunt);

	/*for(unsigned int i = 1; i != 0; i <<= 1){
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

bool HuntRegister::HuntShouldRun(Hunt& hunt, vector<string> vExcludedHunts, vector<string> vIncludedHunts) {
	if (vExcludedHunts.size() != 0) {
		for (auto name : vExcludedHunts) {
			if (hunt.GetName().find(name) != string::npos) {
				return false;
			}
		}
		return true;
	}
	if(vIncludedHunts.size() != 0) {
		for (auto name : vIncludedHunts) {
			if (hunt.GetName().find(name) != string::npos) {
				return true;
			}
		}
		return false;
	}
	return true;
}

bool CallFunctionSafe(const std::function<void()>& func){
	/*__try{
		func();
		return true;
	} __except(EXCEPTION_EXECUTE_HANDLER){
		return false;
	}*/
	//TODO: Purpose of this?
	func();
	return true;
}

void HuntRegister::RunHunts(unsigned int dwTactics, unsigned int dwDataSource, unsigned int dwAffectedThings, const Scope& scope, Aggressiveness aggressiveness, const Reaction& reaction, vector<string> vExcludedHunts, vector<string>vIncludedHunts){
	io.InformUser("Starting a hunt for " + std::to_string(vRegisteredHunts.size()) + " techniques.");
	unsigned int huntsRan = 0;

  for (auto name : vRegisteredHunts) {
	  if (HuntShouldRun(*name, vExcludedHunts, vIncludedHunts)) {
		  int huntRunStatus = 0;
		  auto level = getLevelForHunt(*name, aggressiveness);
		  bool status{ false };
		  status |= level == Aggressiveness::Cursory && CallFunctionSafe([&](){ huntRunStatus = name->ScanCursory(scope, reaction); });
		  status |= level == Aggressiveness::Normal && CallFunctionSafe([&](){ huntRunStatus = name->ScanNormal(scope, reaction); });
		  status |= level == Aggressiveness::Intensive && CallFunctionSafe([&](){ huntRunStatus = name->ScanIntensive(scope, reaction); });
		  if(!status){
			  Bluespawn::io.InformUser("An issue occured in hunt " + name->GetName() + ", preventing it from being run", ImportanceLevel::HIGH);
		  } else if(huntRunStatus != -1){
			  huntsRan++;
		  }
	  }
	}
	if (huntsRan != vRegisteredHunts.size()) {
		io.InformUser("Successfully ran " + std::to_string(huntsRan) + " hunts. There were no scans available for " + std::to_string(vRegisteredHunts.size() - huntsRan) + " of the techniques.");
	}
	else {
		io.InformUser("Successfully ran " + std::to_string(huntsRan) + " hunts.");
	}
}

void HuntRegister::RunHunt(Hunt& hunt, const Scope& scope, Aggressiveness aggressiveness, const Reaction& reaction){
	io.InformUser("Starting scan for " + hunt.GetName());
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
		io.InformUser("No scans for this level available for " + hunt.GetName());
	}
	else {
		io.InformUser("Successfully scanned for " + hunt.GetName());
	}
}

void HuntRegister::SetupMonitoring(Aggressiveness aggressiveness, const Reaction& reaction) {
	//auto& EvtManager = EventManager::GetInstance();
	//TODO
	for (auto name : vRegisteredHunts) {
		auto level = getLevelForHunt(*name, aggressiveness);
		if(name->SupportsScan(level)) {
			io.InformUser("Setting up monitoring for " + name->GetName());
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
					/*unsigned int status = EvtManager.SubscribeToEvent(event, callback);
					if(status != 0){
						LOG_ERROR("Monitoring for " << name->GetName() << " failed with error code " << status);
					}*/
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