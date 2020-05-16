#pragma once

#include <map>

#include "scan/ScanNode.h"

class DetectionCollector {
	std::vector<DetectionNetwork> detections;

public:
	DetectionCollector();

	void AddDetection(const Detection& detection);

	std::vector<Detection> GetAllDetections(Certainty level = Certainty::Moderate);
};