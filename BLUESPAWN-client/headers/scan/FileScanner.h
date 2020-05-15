#pragma once

#include "scan/ScanNode.h"

#include <map>
#include <vector>
#include <set>

class FileScanner {
	static std::map<std::wstring, std::set<DWORD>> modules;
	static FILETIME lastupdate;
	static void UpdateModules();

public:
	static std::map<std::shared_ptr<ScanNode>, Association> FileScanner::GetAssociatedDetections(const std::shared_ptr<ScanNode>& base);
	static Certainty FileScanner::ScanItem(const std::shared_ptr<ScanNode>& detection);
	static std::vector<std::wstring> ExtractFilePaths(const std::vector<std::wstring>& strings);
	static std::vector<std::wstring> ExtractStrings(const AllocationWrapper& data, DWORD dwMinLength = 5);
};