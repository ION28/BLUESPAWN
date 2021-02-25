#include "mitigation/Mitigation.h"

#include "mitigation/MitigationRegister.h"
#include "mitigation/policy/ValuePolicy.h"
#include "mitigation/policy/SubkeyPolicy.h"
#include "mitigation/policy/CombinePolicy.h"
#include "mitigation/policy/EventLogPolicy.h"

#include "util/StringUtils.h"

Mitigation::Mitigation(const std::wstring& name,
                       const std::wstring& description,
                       const Software& software,
                       std::vector<std::unique_ptr<MitigationPolicy>> policies) :
    name{ name },
    description{ description }, software{ software } {
    for(auto& policy : policies){
        this->policies.emplace_back(std::move(policy));
    }
}

Mitigation::Mitigation(json mitigation) : software(L"", L""){
    assert(mitigation.find("name") != mitigation.end());
    assert(mitigation.find("description") != mitigation.end());
    assert(mitigation.find("software") != mitigation.end());
    assert(mitigation.find("policies") != mitigation.end());

    name = StringToWidestring(mitigation["name"].get<std::string>());
    description = StringToWidestring(mitigation["description"].get<std::string>());
    if(mitigation["software"].get<std::string>() == "Windows"){
        software = WindowsOS();
    } else{
        software = Software(StringToWidestring(mitigation["software"].get<std::string>()), 
                            StringToWidestring(mitigation["software-description"].get<std::string>()));
    }
    for(auto& policy : mitigation["policies"]){
        assert(policy.find("policy-type") != policy.end());

        auto type{ policy["policy-type"].get<std::string>() };
        if(type == "registry-value-policy"){
            policies.emplace_back(std::make_unique<ValuePolicy>(policy));
        } else if(type == "registry-subkey-policy"){
            policies.emplace_back(std::make_unique<SubkeyPolicy>(policy));
        } else if(type == "combined-policy"){
            policies.emplace_back(std::make_unique<CombinePolicy>(policy));
        } else if(type == "event-log"){
            policies.emplace_back(std::make_unique<EventLogPolicy>(policy));
        } else{
            throw std::exception(("Unknown mitigation policy type \"" + type + "\"").c_str());
        }
    }
}

std::wstring Mitigation::GetName() const {
    return this->name;
}

std::wstring Mitigation::GetDescription() const {
    return this->description;
}

bool Mitigation::MitigationApplies() const {
    if(!software.IsPresent()) {
        return false;
    }
    auto version{ software.GetVersion() };
    for(auto& policy : policies) {
        if(policy->GetVersionMatch(version)) {
            return true;
        }
    }
    return false;
}

MitigationReport Mitigation::AuditMitigation(const MitigationConfiguration& config) const {
    MitigationReport report{};
    auto version{ software.GetVersion() };
    for(auto& policy : policies) {
        if(policy->GetVersionMatch(version)) {
            try {
                auto match{ policy->MatchesSystem() };
                if(config.manuals.find(policy.get()) != config.manuals.end() ?
                       config.manuals.at(policy.get()) :
                       config.defaultEnforcement >= policy->GetEnforcementLevel()) {
                    report.results.emplace(policy.get(), match ? MitigationReport::PolicyStatus::MatchRequired :
                                                                 MitigationReport::PolicyStatus::NoMatchRequired);
                } else {
                    report.results.emplace(policy.get(), match ? MitigationReport::PolicyStatus::MatchUnrequired :
                                                                 MitigationReport::PolicyStatus::NoMatchUnrequired);
                }
            } catch(std::exception& e) { report.results.emplace(policy.get(), MitigationReport::PolicyStatus::Failed); }
        }
    }
    return report;
}

MitigationReport Mitigation::EnforceMitigation(const MitigationConfiguration& config) const {
    MitigationReport report{ AuditMitigation(config) };
    for(auto& result : report.results) {
        if(result.second == MitigationReport::PolicyStatus::NoMatchRequired ||
           result.second == MitigationReport::PolicyStatus::Failed) {
            try {
                report.results.at(result.first) = result.first->Enforce() ?
                                                      MitigationReport::PolicyStatus::Changed :
                                                      MitigationReport::PolicyStatus::ChangeFailed;
            } catch(std::exception& e) {
                report.results.at(result.first) = MitigationReport::PolicyStatus::ChangeFailed;
            }
        }
    }
    return report;
}

std::vector<MitigationPolicy*> Mitigation::GetPolicies() const {
    std::vector<MitigationPolicy*> copy{};
    for(auto& policy : policies){
        copy.emplace_back(policy.get());
    }
    return copy;
}

bool MitigationReport::Success() const{
    for(auto& pair : results){
        if(pair.second == MitigationReport::PolicyStatus::ChangeFailed ||
           pair.second == MitigationReport::PolicyStatus::Failed){
            return false;
        }
    }
    return true;
}