#include "hunt/Hunt.h"
#include "hunt/HuntRegister.h"
#include "reaction/Reaction.h"

HuntInfo::HuntInfo(const std::string& HuntName, Aggressiveness HuntAggressiveness, unsigned int HuntTactics, unsigned int HuntCategories, unsigned int HuntDatasources) :
	HuntName{ HuntName },
	HuntAggressiveness{ HuntAggressiveness },
	HuntTactics{ HuntTactics },
	HuntCategories{ HuntCategories },
	HuntDatasources{ HuntDatasources }{
	GetSystemTime(&HuntStartTime);
}

Hunt::Hunt(const std::string& name) : 
	name{ name }{
	dwTacticsUsed = 0;
	dwSourcesInvolved = 0;
	dwCategoriesAffected = 0;
	dwSupportedScans = 0;
}

std::string Hunt::GetName() {
	return name;
}

int Hunt::ScanCursory(const Scope& scope, Reaction reaction){
	if(!(dwSupportedScans & (unsigned int) Aggressiveness::Cursory)){
		return -1;
	}
	return 0;
}

int Hunt::ScanNormal(const Scope& scope, Reaction reaction){
	if(!(dwSupportedScans & (unsigned int) Aggressiveness::Normal)){
		return -1;
	}
	return 0;
}

int Hunt::ScanIntensive(const Scope& scope, Reaction reaction){
	if(!(dwSupportedScans & (unsigned int) Aggressiveness::Intensive)){
		return -1;
	}
	return 0;
}

std::vector<std::shared_ptr<Event>> Hunt::GetMonitoringEvents() {
	return std::vector<std::shared_ptr<Event>>();
}

bool Hunt::AffectsCategory(unsigned int dwStuff){
	return (dwStuff && dwCategoriesAffected) == dwStuff;
}

bool Hunt::UsesTactics(unsigned int dwTactics){
	return (dwTactics && dwTacticsUsed) == dwTactics;
}

bool Hunt::UsesSources(unsigned int dwSources){
	return (dwSources && dwSourcesInvolved) == dwSources;
}

bool Hunt::SupportsScan(Aggressiveness aggressiveness){
	return ((unsigned int) aggressiveness & dwSupportedScans) == (unsigned int) aggressiveness;
}