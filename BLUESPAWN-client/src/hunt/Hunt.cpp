#include "hunt/Hunt.h"
#include "hunt/HuntRegister.h"
#include "hunt/reaction/Reaction.h"

#include <iostream>

HuntInfo::HuntInfo(const std::wstring& HuntName, Aggressiveness HuntAggressiveness, DWORD HuntTactics, DWORD HuntCategories, DWORD HuntDatasources, long HuntStartTime) :
	HuntName{ HuntName },
	HuntAggressiveness{ HuntAggressiveness },
	HuntTactics{ HuntTactics },
	HuntCategories{ HuntCategories },
	HuntDatasources{ HuntDatasources },
	HuntStartTime{ HuntStartTime }{}

Hunt::Hunt(HuntRegister& record, const std::wstring& name) : 
	name{ name }{
	record.RegisterHunt(this);

	dwTacticsUsed = 0;
	dwSourcesInvolved = 0;
	dwCategoriesAffected = 0;
	dwSupportedScans = 0;
}

int Hunt::ScanCursory(const Scope& scope, Reaction reaction){
	std::wcout << L"Running hunt handler for " << name << std::endl;
	if(!(dwSupportedScans & (DWORD) Aggressiveness::Cursory)){
		return -1;
	}
	return 0;
}

int Hunt::ScanModerate(const Scope& scope, Reaction reaction){
	if(!(dwSupportedScans & (DWORD) Aggressiveness::Moderate)){
		return -1;
	}
	return 0;
}

int Hunt::ScanCareful(const Scope& scope, Reaction reaction){
	if(!(dwSupportedScans & (DWORD) Aggressiveness::Careful)){
		return -1;
	}
	return 0;
}

int Hunt::ScanAggressive(const Scope& scope, Reaction reaction){
	if(!(dwSupportedScans & (DWORD) Aggressiveness::Aggressive)){
		return -1;
	}
	return 0;
}

bool Hunt::AffectsCategory(DWORD dwStuff){
	return (dwStuff && dwCategoriesAffected) == dwStuff;
}

bool Hunt::UsesTactics(DWORD dwTactics){
	return (dwTactics && dwTacticsUsed) == dwTactics;
}

bool Hunt::UsesSources(DWORD dwSources){
	return (dwSources && dwSourcesInvolved) == dwSources;
}

bool Hunt::SupportsScan(Aggressiveness aggressiveness){
	return ((DWORD) aggressiveness & dwSupportedScans) == (DWORD) aggressiveness;
}