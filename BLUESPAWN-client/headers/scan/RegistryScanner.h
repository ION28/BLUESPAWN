#pragma once

#include "scan/ScanNode.h"

#include <map>
#include <vector>

class RegistryScanner {
public:
	static std::map<ScanNode, Association> GetAssociatedDetections(const ScanNode& node);
	static std::vector<std::wstring> ExtractRegistryKeys(const std::vector<std::wstring>& strings);

	static Certainty ScanItem(ScanNode& node);
};