#pragma once

#include <map>
#include <unordered_set>
#include <queue>

#include "scan/Detections.h"

#include "common/Promise.h"

/**
 * Keeps track of all detections found so far
 */
class DetectionRegister {

	/// A vector containing all detections made
	std::vector<Detection> detections;

	/// CriticalSection guarding accesses to `detections`
	CriticalSection hGuard;

	/// A set containing all detections scanned
	std::unordered_set<std::reference_wrapper<Detection>> scanned;

	/// CriticalSection guarding access to `scanned`
	CriticalSection hScannedGuard;

	/// A set containing all detections found but not done being scanned
	std::unordered_set<std::reference_wrapper<Detection>> queue;

	/// CriticalSection guarding accesses to `queue`.
	CriticalSection hQueueGuard;

	/// Event to be signalled when there are no remaining queued detections
	HandleWrapper hEvent;

	/// The The minimum level of certainty required to search for associated detections
	Certainty threshold;

	/// Called behind the scenes when queueing a scan with AddDetection
	void AddDetectionAsync(
		IN CONST std::reference_wrapper<Detection>& detection,
		IN CONST Certainty& level = Certainty::None OPTIONAL
	);

	/// Used to update the certainty of a detection, possibly triggering assocation scans
	void UpdateDetectionCertainty(
		IN CONST std::reference_wrapper<Detection>& detection,
		IN CONST Certainty& level = Certainty::None OPTIONAL
	);

public:

	/**
	 * Instantiates a new DetectionRegister with a specified threshold for running associativity
	 * scans. 
	 *
	 * @param threshold The minimum level of certainty required to search for associated detections
	 *        for any detection registered
	 */	
	DetectionRegister(
		IN CONST Certainty& threshold
	);

	/**
	 * Adds a task to the threadpool to scan a detection and add it to `detections`. If it is
	 * found to be malicious, associated detections will be identified and added as well. If the
	 * detection already exists, the certainty specified (if any) will be combined with the 
	 * certainty it already has, which may trigger new detections being added.
	 *
	 * @param detection The detection to add
	 * @param level The degree of certainty that this detection is malicious. By default, this is 
	 *              Certainty::None
	 *
	 * @return A reference to the detection added.
	 */
	std::reference_wrapper<Detection> AddDetection(
		IN Detection&& detection, 
		IN CONST Certainty& level = Certainty::None OPTIONAL
	);

	/** 
	 * Retrieves all detections above a specified certainty level. This implicitly calls Wait()
	 *
	 * @param level The minimum certainty of detections to be retrieved
	 * 
	 * @return A vector of detections above the specified level
	 */
	std::vector<std::reference_wrapper<Detection>> GetAllDetections(
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