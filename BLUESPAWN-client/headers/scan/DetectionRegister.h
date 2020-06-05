#pragma once

#include <map>
#include <unordered_set>
#include <queue>

#include "scan/Detections.h"

/**
 * Keeps track of all detections found so far
 */
class DetectionRegister {

	/// A set containing all detections found and scanned
	volatile std::unordered_set<Detection> detections;

	/// CriticalSection guarding accesses to `detections`
	CriticalSection hGuard;

	/// Event to be signalled when there are no remaining queued detections
	HandleWrapper hEvent;

	/// Number of detections queued to be scanned or being scanned
	size_t count;

public:

	/// Instantiates a new detection register. 
	DetectionRegister();

	/**
	 * Adds a task to the threadpool to scan a detection and add it to `detections`. If it is
	 * found to be malicious, associated detections will be identified and added as well. If the
	 * detection already exists, the certainty specified (if any) will be combined with the 
	 * certainty it already has, which may trigger new detections being added.
	 *
	 * @param detection The detection to add
	 * @param level The degree of certainty that this detection is malicious. By default, this is 
	 *              Certainty::None
	 */
	std::reference_wrapper<Detection> AddDetection(
		IN CONST Detection& detection, 
		IN CONST Certainty& level = Certainty::None OPTIONAL
	);

	/** 
	 * Retrieves all detections above a specified certainty level
	 *
	 * @param level The minimum certainty of detections to be retrieved
	 * 
	 * @return A vector of detections above the specified level
	 */
	std::vector<Detection> GetAllDetections(
		IN CONST Certainty& level = Certainty::Moderate OPTIONAL
	) CONST;

	/**
	 * Waits for all queued detections to be finished being scanned. 
	 */
	void Wait() CONST;

	/**
	 * Implicit cast to handle returns an event to be signalled when there are no more detection
	 * scans queued.
	 */
	operator HANDLE() CONST;
};