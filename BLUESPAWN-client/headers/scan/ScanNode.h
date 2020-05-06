#pragma once

#include "reaction/Detections.h"

#include <memory>
#include <vector>

class ScanNode {
	std::vector<std::shared_ptr<ScanNode>> associations;
	Detection detection;

public:
	ScanNode(const Detection& detection);
};