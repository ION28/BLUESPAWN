#include "mitigation/policy/CombinePolicy.h"

CombinePolicy::CombinePolicy(std::vector<std::unique_ptr<MitigationPolicy>> subpolicies, const std::wstring& name,
							 EnforcementLevel level, const std::optional<std::wstring>& description, Mode mode) :
	MitigationPolicy(name, level, description), subpolicies{ std::move(subpolicies) }, mode{ mode }{}

bool CombinePolicy::Enforce() const{
	if(IsEnforced()){
		if(!MatchesSystem()){
			if(mode == Mode::OR){
				if(subpolicies.size()){
					return subpolicies[0]->Enforce();
				}
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