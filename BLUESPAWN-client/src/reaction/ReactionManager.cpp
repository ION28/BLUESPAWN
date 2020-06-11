#include "reaction/ReactionManager.h"

#include <algorithm>  

void ReactionManager::React(IN Detection& detection) CONST {
	EnterCriticalSection(detection.hGuard);
	if(detection.remediator){
		(*detection.remediator)(detection);
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