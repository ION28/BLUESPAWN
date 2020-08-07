#include "hunt/Hunt.h"
#include "hunt/HuntRegister.h"

HuntInfo::HuntInfo(const std::wstring& HuntName, DWORD HuntTactics, DWORD HuntCategories, DWORD HuntDatasources, long HuntStartTime) :
	HuntName{ HuntName },
	HuntTactics{ HuntTactics },
	HuntCategories{ HuntCategories },
	HuntDatasources{ HuntDatasources }, 
	HuntStartTime{ HuntStartTime }{}

Hunt::Hunt(IN CONST std::wstring& name) : 
	name{ name }{
	dwTacticsUsed = 0;
	dwSourcesInvolved = 0;
	dwCategoriesAffected = 0;
}

std::wstring Hunt::GetName() {
	return name;
}

std::vector<std::shared_ptr<Detection>> Hunt::RunHunt(IN CONST Scope& scope){
	return {};
}

std::vector<std::pair<std::unique_ptr<Event>, Scope>> Hunt::GetMonitoringEvents() {
	return std::vector<std::pair<std::unique_ptr<Event>, Scope>>();
}

bool Hunt::AffectsCategory(IN DWORD dwStuff){
	return (dwStuff && dwCategoriesAffected) == dwStuff;
}

bool Hunt::UsesTactics(IN DWORD dwTactics){
	return (dwTactics && dwTacticsUsed) == dwTactics;
}

bool Hunt::UsesSources(IN DWORD dwSources){
	return (dwSources && dwSourcesInvolved) == dwSources;
}
