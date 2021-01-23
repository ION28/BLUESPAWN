#pragma once

#include <set>

#include "mitigation/policy/MitigationPolicy.h"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

/**
 * \brief Implements a MitigationPolicy for enabling event log channels
 */
class EventLogPolicy : public MitigationPolicy {

protected:
	/// The names of subkeys to check for.
	std::set<std::wstring> channelNames;

public:

	/**
	 * \brief Instantiates a MitigationPolicy object from a json configuration. This may throw exceptions.
	 *
	 * \param config The json object storing information about how the policy should be created.
	 */
	EventLogPolicy(json config);

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
