#pragma once

#include "scan/ScanNode.h"

#include <map>
#include <vector>

class FileScanner {
public:
	static std::map<std::shared_ptr<ScanNode>, Association> FileScanner::GetAssociatedDetections(Detection base, Aggressiveness level);
	static std::vector<std::wstring> ExtractFilePaths(const std::vector<std::wstring>& strings);
	static std::vector<std::wstring> ExtractStrings(const AllocationWrapper& data, DWORD dwMinLength = 5);
};