#pragma once

#include <unordered_map>
#include <string>

#include "scan/Detections.h"
#include "scan/Scanner.h"

class RegistryScanner : public Scanner {
public:
	
	/**
	 * Extracts strings that match registry key names under any of the five default hives.
	 *
	 * @param strings The strings to search
	 *
	 * @return a vector of registry paths found in `strings`, including the hives under which they were found.
	 */
	static std::vector<std::wstring> RegistryScanner::ExtractRegistryKeys(
		IN CONST std::vector<std::wstring>& strings
	);

	/**
	 * Gets a vector of detections associated with the provided detection. This is done by finding the associated
	 * item with the registry value, if such a value is present.
	 *
	 * @param detection The detection for which associations will be found
	 *
	 * @return A vector of detections associated with the provided detection
	 */
	virtual std::unordered_map<std::shared_ptr<Detection>, Association> GetAssociatedDetections(
		IN CONST Detection& detection
	);

	/**
	 * Scans a detection and returns the certainty that the detection is malicious. This is done by checking for hidden
	 * information in the value, if such a value is present.
	 *
	 * @param detection The Detection object to scan
	 *
	 * @return A Certainty indicating the degree of certainty for which the detection is malicious
	 */
	virtual Certainty ScanDetection(
		IN CONST Detection& detection
	);
};