#pragma once

#include <unordered_map>
#include <string>

#include "scan/Detections.h"

class ProcessScanner {
private:

	/**
	 * Scans a command for possibly associated detections. The intended use-case of this is to find things
	 * such as malware.exe in the command `cmd.exe /c "malware.exe"`. 
	 */
	std::unordered_map<std::reference_wrapper<Detection>, Association> SearchCommand(
		IN CONST std::wstring& ProcessCommand
	);

public:

	/**
	 * Gets a vector of detections associated with the provided detection. This is done by finding child 
	 * processes and files referenced in the command used to spawn the process.
	 *
	 * @param detection The detection for which associations will be found
	 *
	 * @return A vector of detections associated with the provided detection
	 */
	virtual std::unordered_map<std::reference_wrapper<Detection>, Association> GetAssociatedDetections(
		IN CONST Detection& detection
	);

	/**
	 * This function will return false, as there is no "quick" scan to check if a process may be bad
	 *
	 * @param info Unused
	 *
	 * @return False
	 */
	virtual bool PerformQuickScan(
		IN CONST std::wstring& info
	);

	/**
	 * Scans a detection and returns the certainty that the detection is malicious.
	 *
	 * @param detection The Detection to scan
	 *
	 * @return A Certainty indicating the degree of certainty for which the detection is malicious
	 */
	Certainty ScanDetection(
		IN CONST Detection& detection
	);
};