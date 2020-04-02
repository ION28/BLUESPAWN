#include "reaction/Reaction.h"

void Reaction::BeginHunt(const HuntInfo& info){
	for(auto BeginProc : vStartHuntProcs){
		BeginProc(info);
	}
}
void Reaction::EndHunt(){
	for(auto EndProc : vEndHuntProcs){
		EndProc();
	}
}

void Reaction::FileIdentified(std::shared_ptr<FILE_DETECTION> info){
	for(auto reaction : vFileReactions){
		reaction(info);
	}
}
void Reaction::RegistryKeyIdentified(std::shared_ptr<REGISTRY_DETECTION> info){
	for(auto reaction : vRegistryReactions){
		reaction(info);
	}
}
void Reaction::ProcessIdentified(std::shared_ptr<PROCESS_DETECTION> info){
	for(auto reaction : vProcessReactions){
		reaction(info);
	}
}
void Reaction::ServiceIdentified(std::shared_ptr<SERVICE_DETECTION> info){
	for(auto reaction : vServiceReactions){
		reaction(info);
	}
}
void Reaction::EventIdentified(std::shared_ptr<EVENT_DETECTION> info) {
	for (auto reaction : vEventReactions) {
		reaction(info);
	}
}

void Reaction::AddHuntBegin(HuntStart start){
	vStartHuntProcs.emplace_back(start);
}
void Reaction::AddHuntEnd(HuntEnd end){
	vEndHuntProcs.emplace_back(end);
}

void Reaction::AddFileReaction(DetectFile handler){
	vFileReactions.emplace_back(handler);
}
void Reaction::AddRegistryReaction(DetectRegistry handler){
	vRegistryReactions.emplace_back(handler);
}
void Reaction::AddProcessReaction(DetectProcess handler){
	vProcessReactions.emplace_back(handler);
}
void Reaction::AddServiceReaction(DetectService handler){
	vServiceReactions.emplace_back(handler);
}
void Reaction::AddEventReaction(DetectEvent handler) {
	vEventReactions.emplace_back(handler);
}

Reaction& Reaction::Combine(const Reaction& reaction){

	for(auto function : reaction.vStartHuntProcs)
		vStartHuntProcs.emplace_back(function);
	for(auto function : reaction.vEndHuntProcs)
		vEndHuntProcs.emplace_back(function);
	for(auto function : reaction.vFileReactions)
		vFileReactions.emplace_back(function);
	for(auto function : reaction.vRegistryReactions)
		vRegistryReactions.emplace_back(function);
	for(auto function : reaction.vProcessReactions)
		vProcessReactions.emplace_back(function);
	for(auto function : reaction.vServiceReactions)
		vServiceReactions.emplace_back(function);
	for (auto function : reaction.vEventReactions)
		vEventReactions.emplace_back(function);

	return *this;
}

Reaction& Reaction::Combine(Reaction&& reaction){

	for(auto function : reaction.vStartHuntProcs)
		vStartHuntProcs.emplace_back(function);
	for(auto function : reaction.vEndHuntProcs)
		vEndHuntProcs.emplace_back(function);
	for(auto function : reaction.vFileReactions)
		vFileReactions.emplace_back(function);
	for(auto function : reaction.vRegistryReactions)
		vRegistryReactions.emplace_back(function);
	for(auto function : reaction.vProcessReactions)
		vProcessReactions.emplace_back(function);
	for(auto function : reaction.vServiceReactions)
		vServiceReactions.emplace_back(function);
	for (auto function : reaction.vEventReactions)
		vEventReactions.emplace_back(function);

	return *this;
}