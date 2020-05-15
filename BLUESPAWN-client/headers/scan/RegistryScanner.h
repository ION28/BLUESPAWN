#pragma once

#include "scan/ScanNode.h"

#include <map>
#include <vector>

class RegistryScanner {
public:
	static std::map<std::shared_ptr<ScanNode>, Association> GetAssociatedDetections(const std::shared_ptr<ScanNode>& node);
	static std::vector<std::wstring> ExtractRegistryKeys(const std::vector<std::wstring>& strings);

	static Certainty ScanItem(const std::shared_ptr<ScanNode>& node);
};