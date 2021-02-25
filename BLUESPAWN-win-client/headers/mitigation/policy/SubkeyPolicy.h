#pragma once

#include <set>

#include "mitigation/policy/RegistryPolicy.h"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

using namespace Registry;

/**
 * \brief Implements a RegistryPolicy for enforcement of policies over subkeys of a specified registry key
 */
class SubkeyPolicy : public RegistryPolicy {
    public:
    /**
	 * \brief Describes the manner in the value policy affects the registry
	 */
    enum class SubkeyPolicyType {
        Whitelist,   /// Allow only the subkey names specified by this policy
        Blacklist    /// Do not allow the subkey names specified by this policy
    };

    protected:
    /// The names of subkeys to check for.
    std::set<std::wstring> subkeyNames;

    /// The type of policy to be enforced.
    SubkeyPolicyType policyType;

    public:
    /**
	 * \brief Instantiates a SubkeyPolicy object.
	 *
	 * \param key The registry key associated with this registry policy
	 * \param subkeyNames The names of subkeys this policy looks for. This is interpretted according to the policyType.
	 * \param policyType The policy for how the subkey names provided should be treated.
	 * \param name The name of the mitigation policy. This should attempt to very briefly describe what it does (i.e.
	 *       "Disable Anonymously Accessible Named Pipes")
	 * \param level The level at which this mitigation policy should be begin to be enforced. This should be Low,
	 *        Moderate, or High
	 * \param description An optional explanation for the policy (i.e. "Anonymously accessible named pipes can be used
	 *        in X, Y and Z attacks and should be disabled. See abc.com/xyz for more info [v-123]")
	 * \param min The minimum version of the associated software where this policy applies
	 * \param max The maximum version of the associated software where this policy applies
	 */
    SubkeyPolicy(const RegistryKey& key,
                 const std::vector<std::wstring>& subkeyNames,
                 SubkeyPolicyType policyType,
                 const std::wstring& name,
                 EnforcementLevel level,
                 const std::optional<std::wstring>& description = std::nullopt,
                 const std::optional<Version>& min = std::nullopt,
                 const std::optional<Version>& max = std::nullopt);

    /**
	 * \brief Instantiates a SubkeyPolicy object from a json configuration. This may throw exceptions.
	 *
	 * \param config The json object storing information about how the policy should be created.
	 */
    SubkeyPolicy(json config);

    /**
	 * \brief Enforces the mitgiation policy, applying the change to the system.
	 *
	 * \return True if the system has the mitigation policy enforced; false otherwise.
	 */
    virtual bool Enforce();

    /**
	 * \brief Checks if the changes specified by the mitigation policy match the current state of the system.
	 *
	 * \return True if the system has the changes specified by the mitigation policy enforced; false otherwise.
	 */
    virtual bool MatchesSystem() const;
};
