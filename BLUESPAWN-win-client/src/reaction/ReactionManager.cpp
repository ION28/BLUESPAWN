#include "reaction/ReactionManager.h"

#include "user/bluespawn.h"

#include <algorithm>  

void ReactionManager::React(IN Detection& detection) CONST {
	EnterCriticalSection(detection.hGuard);
	if(detection.remediator && 
	   Bluespawn::io.GetUserConfirm(L"Detection ID " + std::to_wstring(detection.dwID) + L" has a remediator. Use it?",
									-1, ImportanceLevel::MEDIUM)){
		(*detection.remediator)();
		detection.DetectionStale = true;
	}
	std::for_each(reactions.begin(), reactions.end(), [&detection](const auto& f){
		if(f->Applies(detection) && (!detection.remediator || f->IgnoreRemediator)){
			f->React(detection);
		}
	});
	LeaveCriticalSection(detection.hGuard);
}

void ReactionManager::AddHandler(IN std::unique_ptr<Reaction>&& reaction){
	reactions.emplace_back(std::move(reaction));
}