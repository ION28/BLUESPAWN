#pragma once

#include <map>

#include "scan/ScanNode.h"
#include "scan/FileScanner.h"
#include "scan/RegistryScanner.h"
#include "scan/ProcessScanner.h"

class DetectionCollector {
	std::vector<DetectionNetwork> detections;

public:
	DetectionCollector();

	void AddDetection(const Detection& detection);
};