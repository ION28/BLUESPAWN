#pragma once

#include "scan/ScanNode.h"

#include <map>
#include <vector>

class ProcessScanner {
public:
	static std::map<std::shared_ptr<ScanNode>, Association> ProcessScanner::GetAssociatedDetections(Detection base, Aggressiveness level);

	static Certainty ScanItem(const Detection& base, Aggressiveness level);
};