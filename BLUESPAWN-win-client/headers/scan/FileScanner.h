#pragma once

#include "scan/ScanInfo.h"

#include <unordered_map>
#include <vector>
#include <unordered_set>

#include "scan/Scanner.h"

class FileScanner : public Scanner {
	
	/// A mapping of module names to sets of the PIDs of processes with the module loaded
	std::unordered_map<std::wstring, std::unordered_set<DWORD>> modules;

	/// A mapping of hashes to the modules that match the hash
	std::unordered_map<std::wstring, std::unordered_set<std::wstring>> hashes;

	/// The last time that `modules` was updated
	FILETIME ModuleLastUpdateTime;

	/// The rate at which `modules` is updated, in milliseconds
	static const DWORD MODULE_UPDATE_INTERVAL{ 300000 };

	/// CriticalSection guarding access to `modules`, `hashes`, and `ModuleLastUpdateTime`
	CriticalSection hGuard;

	/// Checks if `modules` needs to be updated, and if so, updates it and `ModuleLastUpdateTime`
	void UpdateModules();

public:
	
	/**
	 * Searches through the strings given for strings referencing a file
	 *
	 * @param strings A vector of strings to search
	 *
	 * @return A vector of strings referencing files
	 */
	static std::vector<std::wstring> ExtractFilePaths(
		IN CONST std::vector<std::wstring>& strings
	);

	/** 
	 * Searches through memory for strings (hex range 0x20 to 0x79) of a certain minimum length, either
	 * in ascii or unicode
	 * 
	 * @param data The memory to search through
	 * @param dwMinLength The minimum length of strings being searched for
	 *
	 * @return A vector containing all strings, converted to widestrings
	 */
	static std::vector<std::wstring> ExtractStrings(
		IN CONST AllocationWrapper& data, 
		IN DWORD dwMinLength = 5 OPTIONAL
	);

	/**
	 * Gets a vector of detections associated with the provided detection. This searches for processes with
	 * the file loaded into memory and depending on the aggressiveness, any file paths or registry paths in
	 * the file.
	 *
	 * @param detection The detection to find associations for
	 *
	 * @return A vector of detections associated with the provided detection
	 */
	virtual std::unordered_map<std::shared_ptr<Detection>, Association> GetAssociatedDetections(
		IN CONST Detection& detection
	);

	/**
	 * Performs a fast scan to determine whether the info provided is potentially malicious.
	 * This checks if the file exists, and if so, returns true if the file is not signed.
	 *
	 * @param info A string used to identify some object
	 *
	 * @return True if the object represented by the string is potentially malicious
	 */
	static bool PerformQuickScan(
		IN CONST std::wstring& info
	);

	/**
	 * Scans a detection and returns the certainty that the detection is malicious. This is computed as
	 * a combination of whether the file is signed and which (if any) yara rules it matches
	 *
	 * @param detection The Detection to scan
	 *
	 * @return A Certainty indicating the degree of certainty for which the detection is malicious
	 */
	virtual Certainty ScanDetection(
		IN CONST Detection& detection
	);
};