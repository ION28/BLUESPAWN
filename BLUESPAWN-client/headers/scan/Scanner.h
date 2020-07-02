#pragma once

#include <vector>

#include "scan/Detections.h"
#include "scan/ScanInfo.h"

class Scanner {
public:

	/// A static vector of publically accessible scanners
	static std::vector<std::shared_ptr<Scanner>> scanners;

	/**
	 * Gets a vector of detections associated with the provided detection
	 * 
	 * @param detection The detection to find associations for
	 *
	 * @return A vector of detections associated with the provided detection
	 */
	virtual std::unordered_map<std::shared_ptr<Detection>, Association> GetAssociatedDetections(
		IN CONST Detection& detection
	);

	/**
	 * Scans a detection and returns the certainty that the detection is malicious.
	 *
	 * @param detection The Detection to scan
	 *
	 * @return A Certainty indicating the degree of certainty to which the detection
	 *         is malicious
	 */
	virtual Certainty ScanDetection(
		IN CONST Detection& detection
	);
};