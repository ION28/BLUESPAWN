#pragma once

#include <vector>

#include "scan/Detections.h"
#include "scan/ScanInfo.h"

class Scanner {
public:

	/// A static vector of publically accessible scanners
	static std::vector<Scanner> scanners;

	/**
	 * Gets a vector of detections associated with the provided detection
	 * 
	 * @param detection The detection to find associations for
	 *
	 * @return A vector of detections associated with the provided detection
	 */
	virtual std::unordered_map<Detection, Association> GetAssociatedDetections(
		IN CONST Detection& detection
	);

	/**
	 * Performs a fast scan to determine whether the info provided is potentially malicious.
	 * This can be used to do things like check signatures, find certain keywords, and other
	 * quick tests. A detection object should be created for any object for which this returns
	 * true.
	 *
	 * @param info A string used to identify some object
	 *
	 * @return True if the object represented by the string is potentially malicious
	 */
	virtual bool PerformQuickScan(
		IN CONST std::wstring& info
	);

	/**
	 * Scans a detection and returns the certainty that the detection is malicious.
	 *
	 * @param detection The Detection to scan
	 *
	 * @return A Certainty indicating the degree of certainty to which the detection
	 *         is malicious
	 */
	Certainty ScanDetection(
		IN CONST Detection& detection
	);
};