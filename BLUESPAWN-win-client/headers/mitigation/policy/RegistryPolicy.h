#pragma once

#include "util/configurations/Registry.h"
#include "util/configurations/RegistryValue.h"

#include "mitigation/policy/MitigationPolicy.h"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

using namespace Registry;

/// Forward declare subpolicies here for namespacing purposes
class ValuePolicy;
class SubkeyPolicy;

/**
 * \brief Implements a mitigation policy pertaining to registry settings. This class is abstract;
 *        developers should instead instantiate one of its children describing more accurately what
 *        the policy requires (i.e RegistryPolicy::ValuePolicy)
 */
class RegistryPolicy : public MitigationPolicy {
    /// The keys being referenced by this policy
    std::vector<RegistryKey> keys;

    friend class ValuePolicy;
    friend class SubkeyPolicy;

    protected:
    /**
	 * \brief Instantiates a RegistryPolicy object. This should only be called from withing derived classes'
	 *        constructors.
	 *
	 * \param key The registry key associated with this registry policy
	 * \param name The name of the mitigation policy. This should attempt to very briefly describe what it does (i.e. 
	 *       "Disable Anonymously Accessible Named Pipes")
	 * \param level The level at which this mitigation policy should be begin to be enforced. This should be Low, 
	 *        Moderate, or High
	 * \param description An optional explanation for the policy (i.e. "Anonymously accessible named pipes can be used 
	 *        in X, Y and Z attacks and should be disabled. See abc.com/xyz for more info [v-123]")
	 * \param min The minimum version of the associated software where this policy applies
	 * \param max The maximum version of the associated software where this policy applies
	 */
    RegistryPolicy(const RegistryKey& key,
                   const std::wstring& name,
                   EnforcementLevel level,
                   const std::optional<std::wstring>& description = std::nullopt,
                   const std::optional<Version>& min = std::nullopt,
                   const std::optional<Version>& max = std::nullopt);

    RegistryPolicy(json config);
};
