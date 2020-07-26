#pragma once

#include <functional>

#include "scan/Detections.h"

/// Forward declare ReactionManager to it can be a friend
class ReactionManager;

class Reaction {
    /// Indicates if this reaction runs even if a remediator already exists
    bool IgnoreRemediator = false;

    friend class ReactionManager;

    public:
    /**
	 * React to a detection. The reaction manager will ensure that this reaction
	 * applies to the detection before calling this function.
	 *
	 * @param detection The detection to which the reaction will be applied.
	 */
    virtual void React(IN Detection& detection) = 0;

    /**
	 * Function to determine if this reaction applies to a detection.
	 *
	 * @param detection The detection to check
	 *
	 * @return True if this reaction applies; false otherwise
	 */
    virtual bool Applies(IN CONST Detection& detection) = 0;
};
