#include "mitigation/policy/MitigationPolicy.h"

bool MitigationPolicy::IsEnforced() const{ return isEnforced; }

std::wstring MitigationPolicy::GetPolicyName() const{ return name; }

EnforcementLevel MitigationPolicy::GetEnforcementLevel() const{ return level; }

void MitigationPolicy::SetEnforced(bool enforce){ isEnforced = enforce; }

void MitigationPolicy::SetEnforced(EnforcementLevel level){ isEnforced = level >= this->level; }

MitigationPolicy::MitigationPolicy(const std::wstring& name, EnforcementLevel level, 
								   const std::optional<std::wstring>& description) : name{ name }, level{ level }, 
	                                                                                 description{ description }{}

bool MitigationPolicy::GetVersionMatch(std::optional<Version> version) const{
	if(minVersion == std::nullopt && maxVersion == std::nullopt){
		return true;
	}
	if(version == std::nullopt){
		return false;
	}
	return (!minVersion || *minVersion <= *version) && (!maxVersion || *maxVersion >= *version);
}

