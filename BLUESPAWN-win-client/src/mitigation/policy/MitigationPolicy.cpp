#include "mitigation/policy/MitigationPolicy.h"

#include "util/StringUtils.h"

bool MitigationPolicy::IsEnforced() const{ return isEnforced; }

std::wstring MitigationPolicy::GetPolicyName() const{ return name; }

EnforcementLevel MitigationPolicy::GetEnforcementLevel() const{ return level; }

void MitigationPolicy::SetEnforced(bool enforce){ isEnforced = enforce; }

void MitigationPolicy::SetEnforced(EnforcementLevel level){ isEnforced = level >= this->level; }

std::optional<std::wstring> MitigationPolicy::GetDescription() const{ return this->description; }

MitigationPolicy::MitigationPolicy(const std::wstring& name, EnforcementLevel level, 
								   const std::optional<std::wstring>& description,
								   const std::optional<Version>& min, const std::optional<Version>& max) : 
	name{ name }, level{ level }, description{ description }, minVersion{ min }, maxVersion{ max }{}

MitigationPolicy::MitigationPolicy(json policy){
    assert(policy.find("name") != policy.end());
    assert(policy.find("enforcement-level") != policy.end());

    name = StringToWidestring(policy["name"].get<std::string>());
    description = policy.find("description") != policy.end() ?
        std::optional<std::wstring>(StringToWidestring(policy["description"].get<std::string>())) : std::nullopt;

    auto levelString{ ToLowerCaseA(policy["enforcement-level"].get<std::string>()) };
    if(levelString == "low"){ level = EnforcementLevel::Low; } 
    else if(levelString == "moderate"){ level = EnforcementLevel::Moderate; } 
    else if(levelString == "high"){ level = EnforcementLevel::High; } 
    else throw std::exception(("Unknown enforcement level: " + levelString).c_str());

    minVersion = policy.find("min-software-version") != policy.end() ?
        std::optional<Version>(StringToWidestring(policy["min-software-version"].get<std::string>())) : std::nullopt;
    maxVersion = policy.find("max-software-version") != policy.end() ?
        std::optional<Version>(StringToWidestring(policy["max-software-version"].get<std::string>())) : std::nullopt;
}

bool MitigationPolicy::GetVersionMatch(std::optional<Version> version) const{
	if(minVersion == std::nullopt && maxVersion == std::nullopt){
		return true;
	}
	if(version == std::nullopt){
		return false;
	}
	return (!minVersion || *minVersion <= *version) && (!maxVersion || *maxVersion >= *version);
}

