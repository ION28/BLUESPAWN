#include "hunt/HuntRegister.h"
#include <iostream>

HuntRegister::HuntRegister(IOBase& io) : io(io) {}

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
		if (aggressiveness == Aggressiveness::Intensive) {
			if (name->SupportsScan(Aggressiveness::Intensive)) {
				huntRunStatus = name->ScanIntensive(scope, reaction);
			}
			else if (name->SupportsScan(Aggressiveness::Normal)) {
				huntRunStatus = name->ScanNormal(scope, reaction);
			}
			else {
				huntRunStatus = name->ScanCursory(scope, reaction);
			}
		}
		else if (aggressiveness == Aggressiveness::Normal) {
			if (name->SupportsScan(Aggressiveness::Normal)) {
				huntRunStatus = name->ScanNormal(scope, reaction);
			}
			else {
				huntRunStatus = name->ScanCursory(scope, reaction);
			}
		}
		else {
			huntRunStatus = name->ScanCursory(scope, reaction);
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
	if (aggressiveness == Aggressiveness::Intensive) {
		if (hunt.SupportsScan(Aggressiveness::Intensive)) {
			huntRunStatus = hunt.ScanIntensive(scope, reaction);
		}
		else if (hunt.SupportsScan(Aggressiveness::Normal)) {
			huntRunStatus = hunt.ScanNormal(scope, reaction);
		}
		else {
			huntRunStatus = hunt.ScanCursory(scope, reaction);
		}
	}
	else if (aggressiveness == Aggressiveness::Normal) {
		if (hunt.SupportsScan(Aggressiveness::Normal)) {
			huntRunStatus = hunt.ScanNormal(scope, reaction);
		}
		else {
			huntRunStatus = hunt.ScanCursory(scope, reaction);
		}
	}
	else {
		huntRunStatus = hunt.ScanCursory(scope, reaction);
	}
	if (huntRunStatus == -1) {
		io.InformUser(L"No scans for this level available for " + hunt.GetName());
	}
	else {
		io.InformUser(L"Successfully scanned for " + hunt.GetName());
	}
}