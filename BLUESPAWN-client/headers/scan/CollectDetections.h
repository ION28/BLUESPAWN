#pragma once

#include <map>

#include "scan/ScanNode.h"
#include "scan/FileScanner.h"
#include "scan/RegistryScanner.h"
#include "scan/ProcessScanner.h"

class DetectionCollector {
	std::vector<DetectionNetwork> detections;

	Aggressiveness aggressiveness;

public:
	DetectionCollector(Aggressiveness aggressiveness = Aggressiveness::Normal);

	void AddDetection(const Detection& detection);

	std::vector<DetectionNetwork> Finalize();
};