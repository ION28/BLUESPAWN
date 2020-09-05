#pragma once

#include <unordered_map>
#include <string>

#include "scan/Detections.h"
#include "scan/Scanner.h"

class MemoryScanner : public Scanner {
public:

	/**
	 * Gets a vector of detections associated with the provided detection. This is done by checking if the
	 * memory in question is mapped to a file, and returning the file if so. This also checks for file paths
	 * included in the memory section.
	 *
	 * @param detection The detection for which associations will be found
	 *
	 * @return A vector of detections associated with the provided detection
	 */
	virtual std::unordered_map<std::shared_ptr<Detection>, Association> GetAssociatedDetections(
		IN CONST Detection& detection
	);

	/**
	 * This function will return false, as there is no "quick" scan to check if memory may be bad
	 *
	 * @param info Unused
	 *
	 * @return False
	 */
	virtual bool PerformQuickScan(
		IN CONST std::wstring& info
	);

	/**
	 * Scans a detection and returns the certainty that the detection is malicious. This is done by checking 
	 * memory protections and if the aggressiveness is intensive, scanning the memory with yara.
	 *
	 * @param detection The Detection object to scan
	 *
	 * @return A Certainty indicating the degree of certainty for which the detection is malicious
	 */
	virtual Certainty ScanDetection(
		IN CONST Detection& detection
	);
};