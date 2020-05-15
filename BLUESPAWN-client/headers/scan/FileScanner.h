#pragma once

#include "scan/ScanNode.h"

#include <map>
#include <vector>

class FileScanner {
public:
	static std::map<ScanNode, Association> FileScanner::GetAssociatedDetections(const ScanNode& base);
	static Certainty FileScanner::ScanItem(ScanNode& detection);
	static std::vector<std::wstring> ExtractFilePaths(const std::vector<std::wstring>& strings);
	static std::vector<std::wstring> ExtractStrings(const AllocationWrapper& data, DWORD dwMinLength = 5);
};