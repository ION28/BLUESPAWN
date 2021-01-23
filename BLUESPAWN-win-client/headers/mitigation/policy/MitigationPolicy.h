#pragma once

#include <optional>
#include <string>
#include <vector>

#include "mitigation/Software.h"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

enum class EnforcementLevel {
    None = 0,
    Low = 1,
    Moderate = 2,
    High = 3,
    All = 4,
};

class CombinePolicy;

/**
 * \brief A policy to be enforced by a mitigation. Each mitigation policy represents a single setting,
 *        configuration, or change to be enforced. 
 * 
 * \note When possible, mitigation policies should be extended for types of mitigation policies rather
 *       than for individual mitigations. Mitigation policies involving registry keys, for example, can
 *       be implemented by instantiating a RegistryPolicy and specifying the keys and values in question.
 */
class MitigationPolicy {
    protected:
    /// A boolean tracking whether the policy should be enforced
    bool isEnforced;

    /// The name of the policy. This should attempt to very briefly describe what it does (i.e. "Disable Anonymously
    /// Accessible Named Pipes")
    std::wstring name;

    /// An optional explanation for the policy (i.e. "Anonymously accessible named pipes can be used in X, Y and Z attacks
    /// and should be disabled. See abc.com/xyz for more info [v-123]")
    std::optional<std::wstring> description;

    /// The level at which this mitigaiton policy should begin to be enforced. This should be Low, Moderate, or High
    EnforcementLevel level;

    /// Idenfies the minimum and maximum versions of the software for which this mitigation policy applies.
    std::optional<Version> minVersion, maxVersion;

    friend class CombinePolicy;

    public:
    /**
	 * \brief Instantiates a MitigationPolicy object. This should only be called from withing derived classes' 
	 *        constructors.
	 * 
	 * \param name The name of the mitigation policy. This should attempt to very briefly describe what it does (i.e. 
	 *       "Disable Anonymously Accessible Named Pipes")
	 * \param level The level at which this mitigation policy should be begin to be enforced. This should be Low, 
	 *        Moderate, or High
	 * \param description An optional explanation for the policy (i.e. "Anonymously accessible named pipes can be used 
	 *        in X, Y and Z attacks and should be disabled. See abc.com/xyz for more info [v-123]")
	 * \param min The minimum version of the associated software where this policy applies
	 * \param max The maximum version of the associated software where this policy applies
	 */
    MitigationPolicy(const std::wstring& name,
                     EnforcementLevel level,
                     const std::optional<std::wstring>& description = std::nullopt,
                     const std::optional<Version>& min = std::nullopt,
                     const std::optional<Version>& max = std::nullopt);

    MitigationPolicy(json config);

    /**
	 * \brief Enforces the mitgiation policy, applying the change to the system.
	 * 
	 * \return True if the system has the mitigation policy enforced; false otherwise.
	 */
    virtual bool Enforce() = 0;

    /**
	 * \brief Checks if the changes specified by the mitigation policy match the current state of the
	 *        system.
	 * 
	 * \return True if the system has the changes specified by the mitigation policy enforced; false 
	 *         otherwise.
	 */
    virtual bool MatchesSystem() const = 0;

	/**
	 * \brief Retrieves the name of the mitigation policy
	 *
	 * \return The name of the policy
	 */
	std::wstring GetPolicyName() const;

	/**
	 * \brief Retrieves the description of the mitigation policy
	 *
	 * \return The description of the policy
	 */
	std::optional<std::wstring> GetDescription() const;

    /**
	 * \brief Returns whether or not the mitigation policy is set to be enforced
	 * 
	 * \return True if the mitigation policy is set to be enforced, false otherwise.
	 */
    bool IsEnforced() const;

    /**
	 * \brief Override default enforcement level settings and specify manually whether this policy should be enforced.
	 * 
	 * \param enforced A boolean indicating whether this policy should be enforced.
	 */
    void SetEnforced(bool enforced);

    /**
	 * \brief Set whether or not this policy should be enforced by specifying an enforcement level. If the given level
	 *        is higher than or equal to the policy's enforcement level, the policy will be enforced.
	 *
	 * \param level The level at which the associated mitigation is being enforced.
	 */
    void SetEnforced(EnforcementLevel level);

    /**
	 * \brief Get the minimum level at which the MitigationPolicy will be enforced by default.
	 * 
	 * \return The minimum level at which the MitigationPolicy will be enforced by default.
	 */
    EnforcementLevel GetEnforcementLevel() const;

    /**
	 * \brief Check if the version given meets the required versions for this mitigation policies. 
	 *
	 * \note If nullopt is passed in, this returns true if and only if the min and max versions for this policy are
	 *       both nullopt. If the min or max version is nullopt, it is treated as not having a minimum or maximum 
	 *       version respectively. 
	 */
    bool GetVersionMatch(std::optional<Version> version) const;
};