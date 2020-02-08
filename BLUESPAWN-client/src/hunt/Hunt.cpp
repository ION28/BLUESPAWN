#include "hunt/Hunt.h"
#include "hunt/HuntRegister.h"
#include "hunt/reaction/Reaction.h"

HuntInfo::HuntInfo(const std::wstring& HuntName, Aggressiveness HuntAggressiveness, DWORD HuntTactics, DWORD HuntCategories, DWORD HuntDatasources, long HuntStartTime) :
	HuntName{ HuntName },
	HuntAggressiveness{ HuntAggressiveness },
	HuntTactics{ HuntTactics },
	HuntCategories{ HuntCategories },
	HuntDatasources{ HuntDatasources },
	HuntStartTime{ HuntStartTime }{}

Hunt::Hunt(const std::wstring& name) : 
	name{ name }{
	dwTacticsUsed = 0;
	dwSourcesInvolved = 0;
	dwCategoriesAffected = 0;
	dwSupportedScans = 0;
}

std::wstring Hunt::GetName() {
	return name;
}

int Hunt::ScanCursory(const Scope& scope, Reaction reaction){
	if(!(dwSupportedScans & (DWORD) Aggressiveness::Cursory)){
		return -1;
	}
	return 0;
}

int Hunt::ScanNormal(const Scope& scope, Reaction reaction){
	if(!(dwSupportedScans & (DWORD) Aggressiveness::Normal)){
		return -1;
	}
	return 0;
}

int Hunt::ScanIntensive(const Scope& scope, Reaction reaction){
	if(!(dwSupportedScans & (DWORD) Aggressiveness::Intensive)){
		return -1;
	}
	return 0;
}

void Hunt::SetupMonitoring(HuntRegister& record, const Scope& scope, Aggressiveness level, Reaction reaction) {}

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