#pragma once

#include "scan/ScanNode.h"

#include <map>
#include <vector>

class RegistryScanner {
public:
	static std::map<ScanNode, Association> GetAssociatedDetections(const Detection& base, Aggressiveness level);
	static std::vector<std::wstring> ExtractRegistryKeys(const std::vector<std::wstring>& strings);

	static Certainty ScanItem(const Detection& base, Aggressiveness level);
};