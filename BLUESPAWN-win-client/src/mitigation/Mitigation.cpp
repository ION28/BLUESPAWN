#include "mitigation/Mitigation.h"

#include "mitigation/MitigationRegister.h"

Mitigation::Mitigation(const std::wstring& name,
                       const std::wstring& description,
                       const Software& software,
                       std::initializer_list<std::unique_ptr<MitigationPolicy>> policies) :
    name{ name },
    description{ description }, software{ software } {
    for(auto& policy : policies) {
        this->policies.emplace_back(std::move(policy));
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