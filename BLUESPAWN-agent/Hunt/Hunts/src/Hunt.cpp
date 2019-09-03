#include "hunts/Hunt.h"
#include "hunts/HuntRegister.h"
#include "reactions/Reaction.h"

Hunt::Hunt(HuntRegister& record){
	record.RegisterHunt(this);

	dwTacticsUsed = 0;
	dwSourcesInvolved = 0;
	dwStuffAffected = 0;
	dwSupportedScans = 0;
}

int Hunt::ScanCursory(Scope& scope, Reaction* reaction){
	if(!(dwSupportedScans & Aggressiveness::Cursory)){
		return -1;
	}
	return 0;
}

int Hunt::ScanModerate(Scope& scope, Reaction* reaction){
	if(!(dwSupportedScans & Aggressiveness::Moderate)){
		return -1;
	}
	return 0;
}

int Hunt::ScanCareful(Scope& scope, Reaction* reaction){
	if(!(dwSupportedScans & Aggressiveness::Careful)){
		return -1;
	}
	return 0;
}

int Hunt::ScanAggressive(Scope& scope, Reaction* reaction){
	if(!(dwSupportedScans & Aggressiveness::Aggressive)){
		return -1;
	}
	return 0;
}

bool Hunt::AffectsStuff(DWORD dwStuff){
	return (dwStuff && dwStuffAffected) == dwStuff;
}

bool Hunt::UsesTactics(DWORD dwTactics){
	return (dwTactics && dwTacticsUsed) == dwTactics;
}

bool Hunt::UsesSources(DWORD dwSources){
	return (dwSources && dwSourcesInvolved) == dwSources;
}

bool Hunt::SupportsScan(Aggressiveness::Aggressiveness aggressiveness){
	return (aggressiveness && dwSupportedScans) == aggressiveness;
}