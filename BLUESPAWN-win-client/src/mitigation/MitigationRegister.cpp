#include "mitigation/MitigationRegister.h"

#include "util/StringUtils.h"
#include "util/log/Log.h"
#include "util/permissions/permissions.h"

#include "../resources/resource.h"
#include "nlohmann/json.hpp"
#include "user/CLI.h"
#include "user/bluespawn.h"

using json = nlohmann::json;

EnforcementLevel ParseLevelName(const std::string& levelString) {
    EnforcementLevel level;
    if(levelString == "none") {
        level = EnforcementLevel::None;
    } else if(levelString == "low") {
        level = EnforcementLevel::Low;
    } else if(levelString == "moderate") {
        level = EnforcementLevel::Moderate;
    } else if(levelString == "high") {
        level = EnforcementLevel::High;
    } else if(levelString == "all") {
        level = EnforcementLevel::All;
    } else if(Bluespawn::io.GetUserConfirm(L"Unknown enforcement level: " + StringToWidestring(levelString) +
                                               L"; Set to moderate?",
                                           -1, ImportanceLevel::MEDIUM) == 1) {
        level = EnforcementLevel::Moderate;
    } else {
        Bluespawn::io.InformUser(L"Setting enforcement level to none", ImportanceLevel::HIGH);
        level = EnforcementLevel::None;
    }
    return level;
}

MitigationsConfiguration::MitigationsConfiguration(json config) {
    auto level{ EnforcementLevel::None };
    if(config.find("default-enforcement-level") != config.end()) {
        auto levelString{ ToLowerCaseA(config["default-enforcement-level"].get<std::string>()) };
        level = ParseLevelName(levelString);
    } else {
        Bluespawn::io.InformUser(L"Enforcing no mitigations by default", ImportanceLevel::HIGH);
    }

    for(auto& mitigation : Bluespawn::mitigationRecord.registeredMitigations) {
        configurations.emplace(&mitigation, MitigationConfiguration{ level });
    }

    if(config.find("mitigations") != config.end()) {
        for(auto& mitigationConfig : config["mitigations"]) {
            if(mitigationConfig.find("name") == mitigationConfig.end()) {
                Bluespawn::io.InformUser(L"Skipping malformed mitigation configuration; missing name",
                                         ImportanceLevel::HIGH);
            }

            auto& name{ StringToWidestring(mitigationConfig.at("name").get<std::string>()) };
            bool found{ false };
            for(auto& mitigation : configurations) {
                if(CompareIgnoreCaseW(name, mitigation.first->GetName())) {
                    found = true;

                    if(mitigationConfig.find("enforcement-level") != mitigationConfig.end()) {
                        mitigation.second.defaultEnforcement =
                            ParseLevelName(ToLowerCaseA(mitigationConfig["enforcement-level"].get<std::string>()));
                    }

                    if(mitigationConfig.find("overrides") != mitigationConfig.end()) {
                        for(auto& override : mitigationConfig["overrides"]) {
                            if(override.find("enabled") == override.end()) {
                                Bluespawn::io.InformUser(L"Skipping malformed override policy configuration; missing "
                                                         "`enabled`",
                                                         ImportanceLevel::HIGH);
                            }
                            if(override.find("policy-name") != override.end()) {
                                auto policyName{ StringToWidestring(override.at("policy-name").get<std::string>()) };
                                bool policyFound{ false };
                                for(auto& policy : mitigation.first->GetPolicies()) {
                                    if(CompareIgnoreCaseW(policy->GetPolicyName(), policyName)) {
                                        policyFound = true;
                                        mitigation.second.manuals.emplace(policy, override.at("enabled").get<bool>());
                                    }
                                }
                                if(!policyFound) {
                                    Bluespawn::io.InformUser(L"Skipping override policy configuration for \"" +
                                                                 policyName + L"\"; unknown name",
                                                             ImportanceLevel::HIGH);
                                }
                            } else {
                                Bluespawn::io.InformUser(L"Skipping malformed override policy configuration; missing "
                                                         "`policy-name`",
                                                         ImportanceLevel::HIGH);
                            }
                        }
                    }
                }
            }
            if(!found) {
                Bluespawn::io.InformUser(L"Skipping configuration for \"" + name + L"\"; unknown mitigation",
                                         ImportanceLevel::HIGH);
            }
        }
    }
}

MitigationsConfiguration::MitigationsConfiguration(EnforcementLevel level) {
    for(auto& mitigation : Bluespawn::mitigationRecord.registeredMitigations) {
        configurations.emplace(&mitigation, MitigationConfiguration{ level });
    }
}

MitigationRegister::MitigationRegister() {}

void MitigationRegister::Initialize() {
    auto hRsrcInfo = FindResourceW(nullptr, MAKEINTRESOURCE(DefaultMitigations), L"textfile");
    if(!hRsrcInfo) {
        LOG_ERROR("Unable to load default mitigations");
        throw std::exception("Unable to load default mitigations");
    }

    auto hRsrc = LoadResource(nullptr, hRsrcInfo);
    if(!hRsrc) {
        Bluespawn::io.AlertUser(L"Unable to load default mitigations!", -1, ImportanceLevel::HIGH);
        LOG_ERROR("Unable to load default mitigations");
        throw std::exception("Unable to load default mitigations");
    }

    ParseMitigationsJSON(AllocationWrapper{ LockResource(hRsrc), SizeofResource(nullptr, hRsrcInfo) });
}

std::map<Mitigation*, MitigationReport>
MitigationRegister::EnforceMitigations(const MitigationsConfiguration& config) const {
    std::map<Mitigation*, MitigationReport> results;
    for(auto& mitigation : config.configurations) {
        results.emplace(mitigation.first, mitigation.first->EnforceMitigation(mitigation.second));
    }
    return results;
}

std::map<Mitigation*, MitigationReport>
MitigationRegister::AuditMitigations(const MitigationsConfiguration& config) const {
    std::map<Mitigation*, MitigationReport> results;
    for(auto& mitigation : config.configurations) {
        results.emplace(mitigation.first, mitigation.first->AuditMitigation(mitigation.second));
    }
    return results;
}

void MitigationRegister::PrintMitigationReports(const std::map<Mitigation*, MitigationReport>& reports) const {
    std::wstring output{ L"Mitigation Report:\n" };
    for(auto& pair : reports) {
        output += L"Report for mitigation \"" + pair.first->GetName() + L"\":\n";
        for(auto& policy : pair.second.results) {
            output += L"\tPolicy \"" + policy.first->GetPolicyName() + L"\": ";
            if(policy.second == MitigationReport::PolicyStatus::Changed) {
                output += L"Applied changes\n";
            } else if(policy.second == MitigationReport::PolicyStatus::ChangeFailed) {
                output += L"Failed to apply changes\n";
            } else if(policy.second == MitigationReport::PolicyStatus::Failed) {
                output += L"Failed to audit\n";
            } else if(policy.second == MitigationReport::PolicyStatus::MatchRequired) {
                output += L"System matched required policy\n";
            } else if(policy.second == MitigationReport::PolicyStatus::MatchUnrequired) {
                output += L"System matched unrequired policy\n";
            } else if(policy.second == MitigationReport::PolicyStatus::NoMatchRequired) {
                output += L"System did not match required policy\n";
            } else if(policy.second == MitigationReport::PolicyStatus::NoMatchUnrequired) {
                output += L"System did not match unrequired policy\n";
            } else {
                output += L"Unknown result\n";
            }
        }
    }
    Bluespawn::io.InformUser(output);
}

bool MitigationRegister::ParseMitigationsJSON(const FileSystem::File& file) {
    return ParseMitigationsJSON(file.Read());
}

bool MitigationRegister::ParseMitigationsJSON(const AllocationWrapper& contents) {
    if(contents.GetSize()) {
        try {
            char* buffer = contents.GetAsPointer<char>();
            auto data{ json::parse(nlohmann::detail::span_input_adapter(buffer, contents.GetSize())) };
            if(data.find("mitigations") == data.end()) {
                throw std::exception("unable to find mitigations");
            }
            auto mitigations{ data["mitigations"] };
            for(auto& mitigation : mitigations) {
                registeredMitigations.push_back(Mitigation(mitigation));
            }
            return true;
        } catch(std::exception& e) {
            Bluespawn::io.AlertUser(L"Unable to parse JSON for mitigations! Ensure there are no errors in your "
                                    "configuration file. Error: " + StringToWidestring(e.what()),
                                    -1, ImportanceLevel::HIGH);
            LOG_ERROR("Unable to parse mitigations");
        }
    }
    return false;
}

bool MitigationRegister::CreateConfig(FileSystem::File& file, uint32_t mode) {
    if(!file.GetFileExists()) {
        if(!file.Create()) {
            Bluespawn::io.AlertUser(L"Unable to create configuration file " + file.GetFilePath());
            return false;
        }
    }

    if(!file.HasWriteAccess()) {
        file.TakeOwnership();
        file.GrantPermissions(*Permissions::GetProcessOwner(), GENERIC_WRITE);
    }

    if(!file.HasWriteAccess()) {
        Bluespawn::io.AlertUser(L"Unable to write to configuration file " + file.GetFilePath());
        return false;
    }

    json base;
    base["default-enforcement-level"] = "none";
    if(mode){
        json mitigations = json::array();
        base["mitigations"] = mitigations;
        for(auto& mitigation : registeredMitigations){
            json jsonMitigation;
            jsonMitigation["name"] = WidestringToString(mitigation.GetName());
            jsonMitigation["description"] = WidestringToString(mitigation.GetDescription());
            jsonMitigation["enforcement-level"] = "none";
            if(mode == 2){
                json policies = json::array();
                for(auto& policy : mitigation.GetPolicies()){
                    json jsonPolicy;
                    jsonPolicy["policy-name"] = WidestringToString(policy->GetPolicyName());
                    if(policy->GetDescription()){
                        jsonPolicy["description"] = WidestringToString(*policy->GetDescription());
                    }
                    jsonPolicy["enabled"] = false;
                    policies.emplace_back(jsonPolicy);
                }
                jsonMitigation.emplace("overrides", policies);
            }
            base["mitigations"].emplace_back(jsonMitigation);
        }
    }

    auto dumped{ base.dump(4) };
    return file.Write(dumped.c_str(), 0, dumped.size(), true, false);
}
