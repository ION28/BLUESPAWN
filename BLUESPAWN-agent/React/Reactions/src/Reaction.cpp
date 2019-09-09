#include "reactions/Reaction.h"

void Reaction::FileIdentified(FILE_DETECTION* info){
	for(auto reaction : vFileReactions){
		reaction(info);
	}
}

void Reaction::RegistryKeyIdentified(REGISTRY_DETECTION* info){
	for(auto reaction : vRegistryReactions){
		reaction(info);
	}
}

void Reaction::ProcessIdentified(PROCESS_DETECTION* info){
	for(auto reaction : vProcessReactions){
		reaction(info);
	}
}

void Reaction::ServiceIdentified(SERVICE_DETECTION* info){
	for(auto reaction : vServiceReactions){
		reaction(info);
	}
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

Reaction Reaction::Combine(const Reaction& reaction){
	Reaction combined{};

	for(auto function : vFileReactions)
		combined.vFileReactions.emplace_back(function);
	for(auto function : vRegistryReactions)
		combined.vRegistryReactions.emplace_back(function);
	for(auto function : vProcessReactions)
		combined.vProcessReactions.emplace_back(function);
	for(auto function : vServiceReactions)
		combined.vServiceReactions.emplace_back(function);

	for(auto function : reaction.vFileReactions)
		combined.vFileReactions.emplace_back(function);
	for(auto function : reaction.vRegistryReactions)
		combined.vRegistryReactions.emplace_back(function);
	for(auto function : reaction.vProcessReactions)
		combined.vProcessReactions.emplace_back(function);
	for(auto function : reaction.vServiceReactions)
		combined.vServiceReactions.emplace_back(function);

	return combined;
}

Reaction Reaction::Combine(Reaction&& reaction){
	Reaction combined{};

	for(auto function : vFileReactions)
		combined.vFileReactions.emplace_back(function);
	for(auto function : vRegistryReactions)
		combined.vRegistryReactions.emplace_back(function);
	for(auto function : vProcessReactions)
		combined.vProcessReactions.emplace_back(function);
	for(auto function : vServiceReactions)
		combined.vServiceReactions.emplace_back(function);

	for(auto function : reaction.vFileReactions)
		combined.vFileReactions.emplace_back(function);
	for(auto function : reaction.vRegistryReactions)
		combined.vRegistryReactions.emplace_back(function);
	for(auto function : reaction.vProcessReactions)
		combined.vProcessReactions.emplace_back(function);
	for(auto function : reaction.vServiceReactions)
		combined.vServiceReactions.emplace_back(function);

	return combined;
}