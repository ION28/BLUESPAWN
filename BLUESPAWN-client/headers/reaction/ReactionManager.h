#pragma once
#include <Windows.h>

#include <vector>
#include <string>

#include "reaction/Reaction.h"
#include "hunt/HuntInfo.h"
#include "scan/Detections.h"

/**
 * A container class for handling reactions to various types of detections.
 */
class ReactionManager {
protected: 
	
	/// Handlers for detections
	std::vector<std::unique_ptr<Reaction>> reactions;

public: 

	/**
	 * Runs reactions applying to each detection. Note that if the detection has a remediator,
	 * only reactions with IgnoreRemediator set to true will be run. The caller must acquire the
	 * detection's critical section before attempting to call this function.
	 *
	 * @param detection The detection for which handlers will be run
	 */
	void React(
		IN Detection& detection
	) CONST;

	/**
	 * Adds a handler to be run for each detection
	 *
	 * @param handler A reaction to be added to the manager's list of reactions
	 */
	void AddHandler(
		IN std::unique_ptr<Reaction>&& reaction
	);
};