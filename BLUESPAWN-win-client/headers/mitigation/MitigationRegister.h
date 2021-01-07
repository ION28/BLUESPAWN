#pragma once

#include <map>
#include <vector>
#include <string>

#include "Mitigation.h"
#include "util/wrappers.hpp"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

struct MitigationsConfiguration {
    // MitigationsConfiguration(json config);
    MitigationsConfiguration(EnforcementLevel level);

    std::map<Mitigation*, MitigationConfiguration> configurations;
};

class MitigationRegister {
    std::vector<Mitigation> registeredMitigations{};

    friend class MitigationsConfiguration;

public:
    MitigationRegister();

    void Initialize();

    std::map<Mitigation*, MitigationReport> EnforceMitigations(const MitigationsConfiguration& config) const;
    std::map<Mitigation*, MitigationReport> AuditMitigations(const MitigationsConfiguration& config) const;

    bool ParseMitigationsJSON(const std::wstring& path);
    bool ParseMitigationsJSON(const AllocationWrapper& data);
};
