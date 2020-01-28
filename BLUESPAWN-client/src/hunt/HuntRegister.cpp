#include "hunt/HuntRegister.h"
#include <iostream>

void HuntRegister::RegisterHunt(Hunt* hunt){
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
		switch (aggressiveness) {
		case Aggressiveness::Cursory:
			name->ScanCursory(scope, reaction);
			break;
		case Aggressiveness::Moderate:
			name->ScanModerate(scope, reaction);
			break;
		case Aggressiveness::Careful:
			name->ScanCareful(scope, reaction);
			break;
		case Aggressiveness::Aggressive:
			name->ScanAggressive(scope, reaction);
			break;
		}
	}
}

void HuntRegister::RunHunt(Hunt& name, const Scope& scope, Aggressiveness aggressiveness, const Reaction& reaction){
	switch(aggressiveness) {
	case Aggressiveness::Cursory:
		name.ScanCursory(scope, reaction);
		break;
	case Aggressiveness::Moderate:
		name.ScanModerate(scope, reaction);
		break;
	case Aggressiveness::Careful:
		name.ScanCareful(scope, reaction);
		break;
	case Aggressiveness::Aggressive:
		name.ScanAggressive(scope, reaction);
		break;
	}
}