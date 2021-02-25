#include "mitigation/policy/CombinePolicy.h"

#include "mitigation/policy/ValuePolicy.h"
#include "mitigation/policy/SubkeyPolicy.h"
#include "util/StringUtils.h"

CombinePolicy::CombinePolicy(std::vector<std::unique_ptr<MitigationPolicy>> subpolicies, const std::wstring& name,
							 EnforcementLevel level, const std::optional<std::wstring>& description, Mode mode) :
	MitigationPolicy(name, level, description), subpolicies{ std::move(subpolicies) }, mode{ mode }{
	assert(subpolicies.size() != 0);

	minVersion = subpolicies[0]->minVersion;
	maxVersion = subpolicies[0]->maxVersion;

	for(int idx = 1; idx < subpolicies.size(); idx++){
		if(minVersion != std::nullopt){
			minVersion = subpolicies[idx]->minVersion ? 
				(*subpolicies[idx]->minVersion < *minVersion ? subpolicies[idx]->minVersion : minVersion) : 
				std::nullopt;
		}
		if(maxVersion != std::nullopt){
			maxVersion = subpolicies[idx]->maxVersion ?
				(*subpolicies[idx]->maxVersion < *maxVersion ? subpolicies[idx]->maxVersion : maxVersion) :
				std::nullopt;
		}
	}
}

CombinePolicy::CombinePolicy(json policy) : MitigationPolicy(policy){
	assert(policy.find("mode") != policy.end());
	assert(policy.find("subpolicies") != policy.end());

	auto typeString{ ToLowerCaseA(policy["mode"].get<std::string>()) };
	if(typeString == "and"){ mode = Mode::AND; } 
	else if(typeString == "or"){ mode = Mode::OR; } 
	else throw std::exception(("Unknown combination mode: " + typeString).c_str());

	for(auto& subpolicy : policy["subpolicies"]){
		auto type{ subpolicy["policy-type"].get<std::string>() };
		if(type == "registry-value-policy"){
			subpolicies.emplace_back(std::make_unique<ValuePolicy>(subpolicy));
		} else if(type == "registry-subkey-policy"){
			subpolicies.emplace_back(std::make_unique<SubkeyPolicy>(subpolicy));
		} else if(type == "combined-policy"){
			subpolicies.emplace_back(std::make_unique<CombinePolicy>(subpolicy));
		} else{
			throw std::exception(("Unknown mitigation policy type \"" + type + "\"").c_str());
		}
	}
}

bool CombinePolicy::Enforce(){
	if(IsEnforced()){
		if(!MatchesSystem()){
			if(mode == Mode::OR){
				if(subpolicies.size()){
					return subpolicies[0]->Enforce();
				}
				return false;
			} else{
				bool enforced = true;
				for(auto& subpolicy : subpolicies){
					enforced = enforced && subpolicy->Enforce();
				}
				return enforced;
			}
		} else{
			return true;
		}
	} else return MatchesSystem();
}

bool CombinePolicy::MatchesSystem() const{
	if(mode == Mode::OR){
		for(auto& subpolicy : subpolicies){
			if(subpolicy->MatchesSystem()){
				return true;
			}
		}
		return false;
	} else{
		bool enforced = true;
		for(auto& subpolicy : subpolicies){
			enforced = enforced && subpolicy->MatchesSystem();
		}
		return enforced;
	}
}