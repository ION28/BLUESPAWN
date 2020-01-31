#include "hunt/HuntRegister.h"
#include <iostream>

HuntRegister::HuntRegister(IOBase& io) : io(io) {}

void HuntRegister::RegisterHunt(Hunt* hunt) {
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


void HuntRegister::RunHunts(DWORD dwTactics, DWORD dwDataSource, DWORD dwAffectedThings, Scope& scope, Aggressiveness aggressiveness, const Reaction& reaction){
	for (auto name : vRegisteredHunts) {
		if (aggressiveness == Aggressiveness::Intensive) {
			if (name->SupportsScan(Aggressiveness::Intensive)) {
				name->ScanIntensive(scope, reaction);
			}
			else if (name->SupportsScan(Aggressiveness::Normal)) {
				name->ScanNormal(scope, reaction);
			}
			else {
				name->ScanCursory(scope, reaction);
			}
		}
		else if (aggressiveness == Aggressiveness::Normal) {
			if (name->SupportsScan(Aggressiveness::Normal)) {
				name->ScanNormal(scope, reaction);
			}
			else {
				name->ScanCursory(scope, reaction);
			}
		}
		else {
			name->ScanCursory(scope, reaction);
		}
	}
	io.InformUser(L"Successfully ran " + std::to_wstring(vRegisteredHunts.size()) + L" hunts.");
}

void HuntRegister::RunHunt(Hunt& name, const Scope& scope, Aggressiveness aggressiveness, const Reaction& reaction){
	if (aggressiveness == Aggressiveness::Intensive) {
		if (name.SupportsScan(Aggressiveness::Intensive)) {
			name.ScanIntensive(scope, reaction);
		}
		else if (name.SupportsScan(Aggressiveness::Normal)) {
			name.ScanNormal(scope, reaction);
		}
		else {
			name.ScanCursory(scope, reaction);
		}
	}
	else if (aggressiveness == Aggressiveness::Normal) {
		if (name.SupportsScan(Aggressiveness::Normal)) {
			name.ScanNormal(scope, reaction);
		}
		else {
			name.ScanCursory(scope, reaction);
		}
	}
	else {
		name.ScanCursory(scope, reaction);
	}
}