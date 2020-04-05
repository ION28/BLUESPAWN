#pragma once

#include "reaction/Detections.h"

#include <memory>
#include <vector>

class ScanNode {
	std::vector<std::shared_ptr<ScanNode>> associations;
	std::shared_ptr<DETECTION> detection;

public:
	ScanNode(std::shared_ptr<DETECTION> detection);
};