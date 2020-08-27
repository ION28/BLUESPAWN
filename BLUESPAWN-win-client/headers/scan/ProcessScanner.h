#pragma once

#include <unordered_map>
#include <string>

#include "scan/Detections.h"
#include "scan/Scanner.h"

class ProcessScanner : public Scanner {
private:

	/**
	 * Scans a command for possibly associated detections. The intended use-case of this is to find things
	 * such as malware.exe in the command `cmd.exe /c "malware.exe"`.
	 */
	std::unordered_map<std::shared_ptr<Detection>, Association> SearchCommand(
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
	virtual std::unordered_map<std::shared_ptr<Detection>, Association> GetAssociatedDetections(
		IN CONST Detection& detection
	);

	/**
	 * This function will treat `info` as a command to determine if any process created with that command would
	 * be malicious.
	 *
	 * @param info A command to scan
	 *
	 * @return True if the command appears malicious; false otherwise
	 */
	static bool PerformQuickScan(
		IN CONST std::wstring& info
	);

	/**
	 * Scans a detection and returns the certainty that the detection is malicious.
	 *
	 * @param detection The Detection to scan
	 *
	 * @return A Certainty indicating the degree of certainty for which the detection is malicious
	 */
	virtual Certainty ScanDetection(
		IN CONST Detection& detection
	);
};