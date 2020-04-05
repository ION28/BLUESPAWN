#pragma once

#include "reaction/Detections.h"

#include <vector>
#include <memory>

class Scanner {
public:
	virtual std::vector<std::shared_ptr<DETECTION>> GetAssociatedDetections(std::shared_ptr<DETECTION> base, Aggressiveness level) = 0;
};