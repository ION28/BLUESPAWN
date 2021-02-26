#pragma once

#include "mitigation/policy/RegistryPolicy.h"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

using namespace Registry;

/**
 * \brief Implements a RegistryPolicy for enforcement of policies over registry values
 */
class ValuePolicy : public RegistryPolicy {
public:

	/**
	 * \brief Describes the manner in which a ValuePolicy treats its data
	 */
	enum class ValuePolicyType {
		RequireExact,    /// Require the registry data to match the data provided exactly
		ForbidExact,     /// Forbid the registry data from matching the data provided exactly
		RequireAsSubset, /// Require the registry to hold at least the provided data values
						 /// This only applies for REG_MULTI_SZ registry values.
		RequireSubsetOf, /// Require the registry to hold nothing but the provided data values
						 /// This only applies for REG_MULTI_SZ registry values.
		ForbidSubsetOf,  /// Require the registry to hold none of the provided data values
						 /// This only applies for REG_MULTI_SZ registry values.
		ForbidValue,     /// Require the specified registry value to not appear under the associated key.
	};

protected:

	/// The name of the registry value. Leave empty for the default value.
	std::wstring valueName;

	/// The data referenced by the policy.
	RegistryData data;

	/// An optional replacement for the data. This is only used if the policyType is ForbidExact and the value holds 
	/// the forbidden data. If this is nullopt, the value will be deleted.
	std::optional<RegistryData> replacement;

	/// The type of policy to be enforced.
	ValuePolicyType policyType;

public:

	/**
	 * \brief Instantiates a ValuePolicy object.
	 *
	 * \param key The registry key associated with this registry policy
	 * \param valueName The name of the registry value. Leave empty for the default value.
	 * \param data The data referenced by the policy. This is interpretted according to the policyType.
	 * \param policyType The policy for how the data referenced should be treated.
	 * \param name The name of the mitigation policy. This should attempt to very briefly describe what it does (i.e.
	 *       "Disable Anonymously Accessible Named Pipes")
	 * \param level The level at which this mitigation policy should be begin to be enforced. This should be Low,
	 *        Moderate, or High
	 * \param description An optional explanation for the policy (i.e. "Anonymously accessible named pipes can be used
	 *        in X, Y and Z attacks and should be disabled. See abc.com/xyz for more info [v-123]")
	 * \param replacement An optional replacement for the data. This is only used if the policyType is ForbidExact and 
	 *        the value holds the forbidden data. If this is nullopt, the value will be deleted.
	 * \param min The minimum version of the associated software where this policy applies
	 * \param max The maximum version of the associated software where this policy applies
	 */
	ValuePolicy(const RegistryKey& key, const std::wstring& valueName, const RegistryData& data, 
				ValuePolicyType policyType, const std::wstring& name, EnforcementLevel level, 
				const std::optional<std::wstring>& description = std::nullopt, 
				const std::optional<RegistryData>& replacement = std::nullopt,
				const std::optional<Version> & min = std::nullopt, const std::optional<Version> & max = std::nullopt);

	/**
	 * \brief Instantiates a ValuePolicy object from a json configuration. This may throw exceptions.
	 * 
	 * \param config The json object storing information about how the policy should be created.
	 */
	ValuePolicy(json config);

	/**
	 * \brief Enforces the mitgiation policy, applying the change to the system.
	 *
	 * \return True if the system has the mitigation policy enforced; false otherwise.
	 */
	virtual bool Enforce() override;

	/**
	 * \brief Checks if the changes specified by the mitigation policy match the current state of the
	 *        system.
	 *
	 * \return True if the system has the changes specified by the mitigation policy enforced; false
	 *         otherwise.
	 */
	virtual bool MatchesSystem() const override;
};