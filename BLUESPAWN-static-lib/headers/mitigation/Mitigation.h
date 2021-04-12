#pragma once

#include <map>

#include "mitigation/Software.h"
#include "mitigation/policy/MitigationPolicy.h"

#include "nlohmann/json.hpp"

using json = nlohmann::json;

/**
 * \brief Describes how a mitigation should be applied to the system by specifying a default enforcement level and 
 *        providing a list of mitigation policies for which the default application should be overriden.
 */
struct MitigationConfiguration {
    /// The level of enforcement to apply for mitigation policies not overriden in `manuals`
    EnforcementLevel defaultEnforcement;

    /// A mapping from mitigation policies to booleans indicating whether the associated policies should be enforced.
    /// This takes precedence over the default enforcement level
    std::map<MitigationPolicy*, bool> manuals;
};

/**
 * \brief Stores the results of enforcing or auditing a mitigation.
 */
struct MitigationReport {
    /**
	 * \brief Refers to the enforcement status of a MitigationPolicy. 
	 * 
	 * \note When auditing the system, and PolicyStatus generated will be one of NoMatchUnrequired, NoMatchRequired,
	 *       MatchUnrequired, Failed, or MatchRequired. When enforcing, this will instead be one of NoMatchUnrequired,
	 *       MatchUnrequired, MatchRequired, Changed, or ChangeFailed.
	 */
    enum class PolicyStatus {
        NoMatchUnrequired,  // The system state required by the policy is unmet, and the policy is not required
        NoMatchRequired,    // The system state required by the policy is unmet, and the policy is required
        MatchUnrequired,    // The system state required by the policy is met, and the policy is not required
        MatchRequired,      // The system state required by the policy is met, and the policy is required
        Changed,            // The system state was changed to match that required by the policy
        ChangeFailed,       // The system state required by the policy is unmet, and the required state couldn't be met
        Failed,             // The system state relevant to the policy could not be checked
    };

    /// Stores the enforcement status for all MitigationPolicies
    std::map<MitigationPolicy*, PolicyStatus> results;

    /**
     * \brief Indicates whether the audit or enforcement was a success.
     * 
     * \note An audit is a success if no MitigationPolicy's resulted in PolicyStatus::Failed. An enforcement is a 
     *       success if no MitigationPolicy's resulted in ChangeFailed.
     */
    bool Success() const;
};

/**
 * \brief Represents a mitigation that may be applied to the system. 
 *
 * \note For mitigations that apply to the OS, each MITRE mitigation technique should be a separate mitigation.
 *       For mitigations that apply to a single software package, each software package should
 */
class Mitigation {
    /// The name of the mitigation. This should be either the MITRE mitigation technique or specify the name of the
    /// software to which the mitigation applies (i.e. "Apply M1047 - Audit" or "Mitigations for FileZilla 3.52")
    std::wstring name;

    /// Describes the changes made by the mitigation at a high level (i.e. "Enforce binary and application integrity
    /// with digital signature verification to prevent untrusted code from executing.")
    std::wstring description;

    /// The software package targetted by this mitigation. If the mitigation targets the operating system, this should
    /// be "Windows"
    Software software;

    /// The policies enforced by this mitigation.
    std::vector<std::unique_ptr<MitigationPolicy>> policies;

    public:
    /**
	 * \brief Instantiates a mitigation object
	 * 
	 * \note See the documentation for the members of this class for more detail on what the arguments should be
	 * 
	 * \param name The name of the mitigation
	 * \param description The description of what the mitigation does
	 * \param software The software package targetted by this mitigation
	 * \param policies The mitigation policies to be enforced by this mitigation
	 */
    Mitigation(const std::wstring& name,
               const std::wstring& description,
               const Software& software,
               std::vector<std::unique_ptr<MitigationPolicy>> policies);

    Mitigation(json mitigation);

    /**
	 * \brief Compares the current state of the system against the requirements set forth by the mitigation policies.
	 *        Returns a MitigationReport describing the enforcement state of the mitigation policies.
	 * 
	 * \param config A configuration describing which mitigation policies should be considered required. See 
	 *        documentation for MitigationConfiguration for more information.
	 * 
	 * \return A MitigationReport describing the enforcement state of the mitigation policies.
	 */
    MitigationReport AuditMitigation(const MitigationConfiguration& config) const;

    /**
	 * \brief Compares the current state of the system against the requirements set forth by the mitigation policies.
	 *        Enforces any mitigation policies required that are not already in effect. 
	 *
	 * \param config A configuration describing which mitigation policies should be enforced. See documentation for
	 *        MitigationConfiguration for more information.
	 *
	 * \return A MitigationReport describing the enforcement state of the mitigation policies and the result of trying
	 *         to enforce any mitigation policies.
	 */
    MitigationReport EnforceMitigation(const MitigationConfiguration& config) const;

    /**
	 * \brief Checks if the mitigation applies to the system by ensuring the associated software is present and 
	 */
    virtual bool MitigationApplies() const;

    /**
     * \brief Retrieves the name of the mitigation
     * 
     * \return The name of the mitigation
     */
    std::wstring GetName() const;

    /**
     * \brief Retrieves the description of the mitigation
     *
     * \return The description of the mitigation
     */
    std::wstring GetDescription() const;

    /**
     * \brief Retrieves a vector of non-owning pointers to all mitigation policies in this mitigation
     * 
     * \return A vector of non-owning pointers to all mitigation policies in this mitigation
     */
    std::vector<MitigationPolicy*> GetPolicies() const;
};
