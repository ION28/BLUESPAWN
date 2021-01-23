#pragma once

#include <memory>
#include <vector>

#include "mitigation/policy/MitigationPolicy.h"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

/**
 * \brief Combines two or more mitigation policy objects into just one object. The policy may require all of or just 
 *        one of the policies being combined to be enforced.
 */
class CombinePolicy : public MitigationPolicy {
    /// Stores pointers to the MitigationPolicies being combined
    std::vector<std::unique_ptr<MitigationPolicy>> subpolicies;

    public:
    /**
	 * \brief Refers to an enforcement mode for the policy. It may require all subpolicies to be enforced, or just one.
	 */
    enum class Mode {
        OR,   /// Requires just one subpolicy to be enforced
        AND   /// Requires that all subpolicies be enforced
    };

    protected:
    /// Tracks the mode of this mitigation policy
    Mode mode;

    public:
    /**
	 * \brief Constructs a CombinePolicy object with the specified subpolicies and mode, defaulting to requiring all 
	 *        subpolicies to be enforced.
	 * 
	 * \param subpolicies A vector of unique pointers to the subpolicies to be combined by the created CombinePolicy
	 * \param mode The enforcement mode for this CombinePolicy, which specifies whether just one or all subpolicies 
	 *        should be enforced.
	 * \param name The name of the mitigation policy. This should attempt to very briefly describe what it does (i.e. 
	 *       "Disable Anonymously Accessible Named Pipes")
	 * \param level The level at which this mitigation policy should be begin to be enforced. This should be Low, 
	 *        Moderate, or High
	 * \param description An optional explanation for the policy (i.e. "Anonymously accessible named pipes can be used 
	 *        in X, Y and Z attacks and should be disabled. See abc.com/xyz for more info [v-123]")
	 * \param min The minimum version of the associated software where this policy applies
	 * \param max The maximum version of the associated software where this policy applies
	 */
    CombinePolicy(std::vector<std::unique_ptr<MitigationPolicy>> subpolicies,
                  const std::wstring& name,
                  EnforcementLevel level,
                  const std::optional<std::wstring>& description = std::nullopt,
                  Mode mode = Mode::AND);

    /**
	 * \brief Instantiates a CombinePolicy object from a json configuration. This may throw exceptions.
	 *
	 * \param config The json object storing information about how the policy should be created.
	 */
    CombinePolicy(json config);

    /**
	 * \brief Enforces the mitgiation policy, applying the change to the system. If the policy does not currently match
	 *        the system if the enforcement mode is OR, only the first subpolicy specified when constructed will be 
	 *        enforced.
	 *
	 * \return True if the system has the mitigation policy enforced; false otherwise.
	 */
    virtual bool Enforce();

    /**
	 * \brief Checks if the changes specified by the subpolicies and mode match the current state of the system.
	 *
	 * \return True if the system has the changes specified by the mitigation policy enforced; false otherwise.
	 */
    virtual bool MatchesSystem() const;
};
