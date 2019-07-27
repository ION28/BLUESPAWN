#include "hunts/HuntRegister.h"

void HuntRegister::RegisterHunt(Hunt* hunt){
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


void HuntRegister::RunHunts(DWORD dwTactics, DWORD dwDataSource, DWORD dwAffectedThings, Scope& scope, Aggressiveness::Aggressiveness aggressiveness, Reaction* reaction){
	for (Hunt * hRegisteredHunt : vRegisteredHunts) {
		Hunt& name = *hRegisteredHunt;
		switch (aggressiveness) {
		case Aggressiveness::Cursory:
			if (reaction) name.ScanCursory(scope, reaction); else name.ScanCursory(scope);
			break;
		case Aggressiveness::Moderate:
			if (reaction) name.ScanModerate(scope, reaction); else name.ScanModerate(scope);
			break;
		case Aggressiveness::Careful:
			if (reaction) name.ScanCareful(scope, reaction); else name.ScanCareful(scope);
			break;
		case Aggressiveness::Aggressive:
			if (reaction) name.ScanAggressive(scope, reaction); else name.ScanAggressive(scope);
			break;
		}
	}
}

void HuntRegister::RunHunt(Hunt& name, Scope& scope, Aggressiveness::Aggressiveness aggressiveness, Reaction* reaction){
	switch(aggressiveness){
	case Aggressiveness::Cursory:
		if(reaction) name.ScanCursory(scope, reaction); else name.ScanCursory(scope);
		break;
	case Aggressiveness::Moderate:
		if(reaction) name.ScanModerate(scope, reaction); else name.ScanModerate(scope);
		break;
	case Aggressiveness::Careful:
		if(reaction) name.ScanCareful(scope, reaction); else name.ScanCareful(scope);
		break;
	case Aggressiveness::Aggressive:
		if(reaction) name.ScanAggressive(scope, reaction); else name.ScanAggressive(scope);
		break;
	}
}