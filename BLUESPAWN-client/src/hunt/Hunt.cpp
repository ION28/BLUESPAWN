#include "hunt/Hunt.h"
#include "hunt/HuntRegister.h"
#include "reaction/Reaction.h"

HuntInfo::HuntInfo(const std::wstring& HuntName, DWORD HuntTactics, DWORD HuntCategories, DWORD HuntDatasources, long HuntStartTime) :
	HuntName{ HuntName },
	HuntTactics{ HuntTactics },
	HuntCategories{ HuntCategories },
	HuntDatasources{ HuntDatasources },
	HuntStartTime{ HuntStartTime }{}

Hunt::Hunt(const std::wstring& name) : 
	name{ name }{
	dwTacticsUsed = 0;
	dwSourcesInvolved = 0;
	dwCategoriesAffected = 0;
}

std::wstring Hunt::GetName() {
	return name;
}

std::vector<Detection> Hunt::RunHunt(const Scope& scope){
	return {};
}

std::vector<std::shared_ptr<Event>> Hunt::GetMonitoringEvents() {
	return std::vector<std::shared_ptr<Event>>();
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