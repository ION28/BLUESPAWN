#include "scan/CollectDetections.h"

DetectionCollector::DetectionCollector(Aggressiveness aggressiveness) : aggressiveness{ aggressiveness }{}

void DetectionCollector::AddDetection(const Detection& detection){
	DetectionNetwork& network{ detection };
	for(auto& net : detections){
		if(net.IntersectsNetwork(network)){
			return;
		}
	}

	network.GrowNetwork(aggressiveness);

	// A smart data structure would likely speed this up
	// TODO: run BLUESPAWN through a profiler and see how big of an issue this is...
	for(unsigned i = 0; i < detections.size(); i++){
		if(detections[i].IntersectsNetwork(network)){
			network = network.MergeNetworks(detections[i]);
			detections.erase(detections.begin() + i);
			i--;
		}
	}

	detections.emplace_back(network);
}