#include "scan/ScanNode.h"

#include <queue>
#include <set>

#include "scan/RegistryScanner.h"
#include "scan/FileScanner.h"
#include "scan/ProcessScanner.h"

#include "user/bluespawn.h"

const Certainty Certainty::Certain =  1.00;
const Certainty Certainty::Strong =   0.75;
const Certainty Certainty::Moderate = 0.50;
const Certainty Certainty::Weak =     0.25;
const Certainty Certainty::None =     0.00;

Certainty::Certainty(double certainty) : confidence{ certainty }{}
Certainty::operator double(){ return confidence; }
Certainty Certainty::operator*(Certainty c){ return confidence * c.confidence; }
Certainty Certainty::operator+(Certainty c){ return 1 - (1 - confidence) * (1 - c.confidence); }
bool Certainty::operator==(Certainty c){ return c.confidence > confidence ? c.confidence - confidence <= 0.125 : confidence - c.confidence <= 0.125; }
bool Certainty::operator!=(Certainty c){ return c.confidence > confidence ? c.confidence - confidence > 0.125 : confidence - c.confidence > 0.125; }
bool Certainty::operator>=(Certainty c){ return *this > c || *this == c; }
bool Certainty::operator<=(Certainty c){ return *this > c || *this == c; }
bool Certainty::operator>(Certainty c){ return confidence > c.confidence; }
bool Certainty::operator<(Certainty c){ return confidence < c.confidence; }

std::atomic<DWORD> ScanNode::IDCounter{ 1 };

ScanNode::ScanNode(const Detection& detection) : 
	detection{ detection },
	certainty{ Certainty::None },
	cAssociativeCertainty{ Certainty::None },
	associations{},
	dwID{ IDCounter += 1 },
	bAssociativeStale{ true }{}

void MergeMaps(std::map<std::shared_ptr<ScanNode>, Association>& destination, const std::map<std::shared_ptr<ScanNode>, Association>& source){
	for(auto& pair : source){
		if(destination.find(pair.first) == destination.end()){
			destination.emplace(pair);
		} else{
			auto& entry{ destination.at(pair.first) };
			entry = AddAssociation(entry, pair.second);
		}
	}
}

const std::map<std::shared_ptr<ScanNode>, Association>& ScanNode::GetAssociations(const std::shared_ptr<ScanNode>& node){
	MergeMaps(node->associations, RegistryScanner::GetAssociatedDetections(node));
	MergeMaps(node->associations, FileScanner::GetAssociatedDetections(node));
	MergeMaps(node->associations, ProcessScanner::GetAssociatedDetections(node));

	return node->associations;
}

bool ScanNode::operator==(const ScanNode& node) const{
	if(node.detection->Type == detection->Type){
		switch(detection->Type){
			case DetectionType::Event:
				return static_pointer_cast<EVENT_DETECTION>(detection)->rawXML ==
					static_pointer_cast<EVENT_DETECTION>(node.detection)->rawXML;
			case DetectionType::File:
				return static_pointer_cast<FILE_DETECTION>(detection)->wsFilePath ==
					static_pointer_cast<FILE_DETECTION>(node.detection)->wsFilePath;
			case DetectionType::Other: {
				auto& d1 = static_pointer_cast<OTHER_DETECTION>(detection);
				auto& d2 = static_pointer_cast<OTHER_DETECTION>(detection);
				return d1->type == d2->type && d1->params == d2->params;
			}
			case DetectionType::Process: {
				auto& d1 = static_pointer_cast<PROCESS_DETECTION>(detection);
				auto& d2 = static_pointer_cast<PROCESS_DETECTION>(detection);
				return d1->PID == d2->PID && d1->lpAllocationBase == d2->lpAllocationBase && d1->dwAllocationSize == d2->dwAllocationSize;
			}
			case DetectionType::Registry:
				return static_pointer_cast<REGISTRY_DETECTION>(detection)->value ==
					static_pointer_cast<REGISTRY_DETECTION>(node.detection)->value;
			case DetectionType::Service: {
				auto& d1 = static_pointer_cast<SERVICE_DETECTION>(detection);
				auto& d2 = static_pointer_cast<SERVICE_DETECTION>(detection);
				return d1->wsServiceName == d2->wsServiceName && d1->wsServiceExecutablePath == d2->wsServiceExecutablePath;
			}
			default:
				return false;
		}
	} else return false;
}

bool ScanNode::operator<(const ScanNode& node) const{ 
	return dwID < node.dwID;
}

Certainty ScanNode::GetCertainty(){ 
	if(bAssociativeStale){
		cAssociativeCertainty = Certainty::None;
		for(auto& pair : associations){
			cAssociativeCertainty = ::AddAssociation(cAssociativeCertainty, MultiplyAssociation(pair.first->certainty, pair.second));
		}

		bAssociativeStale = false;
	}
	return ::AddAssociation(certainty, cAssociativeCertainty); 
};

void ScanNode::AddAssociation(const std::shared_ptr<ScanNode>& node, Association a){
	bAssociativeStale = true;
	if(associations.find(node) == associations.end()){
		associations.emplace(node, a);
	} else{
		auto& assoc{ associations.at(node) };
		assoc = ::AddAssociation(assoc, a);
	}
}

void DetectionNetwork::GrowNetwork(){
	std::queue<std::shared_ptr<ScanNode>> queue{};
	std::set<std::shared_ptr<ScanNode>> grew(nodes.begin(), nodes.end());
	std::set<std::shared_ptr<ScanNode>> queued{};

	// Algorithm:
	// Perform a breadth first search with following conditions
	// ScanNodes are treated as the vertices in the graphs. Their associations are the edges.
	// When visiting a node, always call ScanNode first, and set its certainty accordingly.
	// When visiting a node, call GetAssociations if and only if its certainty is medium or greater.

	for(auto& node : nodes){
		RegistryScanner::ScanItem(node);
		FileScanner::ScanItem(node);
		ProcessScanner::ScanItem(node);

		auto& associations{ ScanNode::GetAssociations(node) };
		for(auto& pair : associations){
			if(!grew.count(pair.first) && !queued.count(pair.first)){
				queue.emplace(pair.first);
				queued.emplace(pair.first);
			}
		}
	}

	while(queue.size()){
		auto node{ queue.front() };
		queue.pop();

		RegistryScanner::ScanItem(node);
		FileScanner::ScanItem(node);
		ProcessScanner::ScanItem(node);
		
		if(node->GetCertainty() >= Certainty::Moderate || !nodes.size()){
			grew.emplace(node);

			auto& associations{ ScanNode::GetAssociations(node) };
			for(auto& pair : associations){
				if(!grew.count(pair.first) && !queued.count(pair.first)){
					queue.emplace(pair.first);
					queued.emplace(pair.first);
				}
			}
		}

		if(node->GetCertainty() > Certainty::Weak){
			nodes.emplace_back(node);
		}

		queued.erase(node);
	}
}

bool DetectionNetwork::IntersectsNetwork(const DetectionNetwork& network){
	std::set<std::shared_ptr<ScanNode>> set(nodes.begin(), nodes.end());
	for(auto& node : network.nodes){
		if(set.count(node))
			return true;
	}

	return false;
}

DetectionNetwork::DetectionNetwork(std::vector<std::shared_ptr<ScanNode>>&& nodes) :
	nodes(std::move(nodes)){}

DetectionNetwork::DetectionNetwork(const std::shared_ptr<ScanNode>& node) :
	nodes{ node }{}

DetectionNetwork DetectionNetwork::MergeNetworks(const DetectionNetwork& network) const{
	std::set<std::shared_ptr<ScanNode>> combined(nodes.begin(), nodes.end());
	std::vector<std::shared_ptr<ScanNode>> list(nodes.begin(), nodes.end());

	for(auto& node : network.nodes){
		if(combined.count(node)){
			for(auto& base : list){
				if(base == node){
					MergeMaps(base->associations, node->associations);
				}
			}
		} else list.emplace_back(node);
	}

	return DetectionNetwork{ std::move(list) };
}