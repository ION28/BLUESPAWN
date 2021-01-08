#pragma once

#include <map>
#include <vector>
#include <string>

#include "Mitigation.h"
#include "util/wrappers.hpp"
#include "util/filesystem/FileSystem.h"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

/**
 * \brief Describes a configuration for running mitigations
 */
struct MitigationsConfiguration {

    /**
     * \brief Creates a MitigationConfiguration object by parsing JSON describing the configuration
     * 
     * \param config The JSON configuration describing the configuration
     */
    MitigationsConfiguration(json config);

    /**
     * \brief Creates a MitigationConfiguration that only specifies a single enforcement level for all mitigations
     * 
     * \param level The enforcement level for all mitigations
     */
    MitigationsConfiguration(EnforcementLevel level);

    /// A mapping from pointers to mitigations to the configuration under which the associated mitigation should run
    std::map<Mitigation*, MitigationConfiguration> configurations;
};

/**
 * \brief Stores mitigations, manages parsing new mitigations from JSON, and provides an interface for auditing and
 *        enforcing mitigations
 */
class MitigationRegister {

    /// Records a list of mitigations
    std::vector<Mitigation> registeredMitigations{};

    friend class MitigationsConfiguration;

public:

    /**
     * \brief Instantiates a new MitigationRegister. This is intended to only be used by the Bluespawn class
     */
    MitigationRegister();

    /**
     * \brief Parses the JSON storing the default mitigations and loads them into the list of registered mitigations
     */
    void Initialize();

    /**
     * \brief Enforces mitigations as described in the provided configuration. This changes the system state to match
     *        that described by the mitigation policies.
     * 
     * \param config A configuration describing the level at which each mitigation should be run and any mitigation
     *        policies that should be treated specially
     * 
     * \return A mapping from mitigation pointers to MitigationReport objects describing the results of the enforcement
     *         of each mitigation policy.
     */
    std::map<Mitigation*, MitigationReport> EnforceMitigations(const MitigationsConfiguration& config) const;

    /**
     * \brief Audits mitigations as described in the provided configuration. This does not modify the system state.
     *
     * \param config A configuration describing the level at which each mitigation should be run and any mitigation
     *        policies that should be treated specially
     *
     * \return A mapping from mitigation pointers to MitigationReport objects describing the results of the enforcement
     *         of each mitigation policy.
     */
    std::map<Mitigation*, MitigationReport> AuditMitigations(const MitigationsConfiguration& config) const;

    /**
     * \brief Parses mitigations stored in JSON in the given file. This will fail if the file does not exist or 
     *        contains invalid JSON.
     * 
     * \note The fields required by the JSON configuration are described on the Bluespawn GitHub Wiki
     * 
     * \param file A File object referring to the file containing JSON describing mitigations to add.
     * 
     * \return A boolean indicating whether the mitigations were successfully parsed and loaded into this 
     *         MitigationRegister 
     */
    bool ParseMitigationsJSON(const FileSystem::File& file);

    /**
     * \brief Prints a mitigation report to the Bluespawn IO stream.
     * 
     * \param reports The return value from either AuditMitigations or EnforceMitigations
     */
    void PrintMitigationReports(const std::map<Mitigation*, MitigationReport>& reports) const;

    /**
     * \brief Parses mitigations stored in JSON in the given region of memory. This will fail if the memory is empty
     *        or contains invalid JSON.
     *
     * \note The fields required by the JSON configuration are described on the Bluespawn GitHub Wiki
     *
     * \param data An allocation wrapper referring to a region of memory containing ascii JSON describing mitigations 
     *        to add.
     *
     * \return A boolean indicating whether the mitigations were successfully parsed and loaded into this
     *         MitigationRegister
     */
    bool ParseMitigationsJSON(const AllocationWrapper& data);

    /**
     * \brief Creates a JSON configuration file that can be parsed as a MitigationsConfiguration to specify which
     *        mitigation policies should and should not be run. Everything will be configured to not run by default.
     * 
     * \param outfile The file to which the information should be written. Overwrites existing files.
     * \param mode Specifies what the JSON configuration should include. Options are listed below.
     *        0 - Create a configuration file with only a global default enforcement level
     *        1 - Create a configuration file with a global default enforcement level and an enforcement level for
     *            each mitigation
     *        2 - Creates a configuration file with a global default enforcement level, an enforcement level for each
     *            mitigation, and an override for each mitigation policy
     */
    bool CreateConfig(FileSystem::File& outfile, uint32_t mode);
};
