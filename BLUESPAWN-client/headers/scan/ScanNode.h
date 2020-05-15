#pragma once

#include "reaction/Detections.h"

#include <memory>
#include <vector>
#include <map>

/// Represents the degree of certainty that a detection is malicious
enum class Certainty {
	Certain = 0,  // 1.00
	Strong = 1,   // 0.75
	Moderate = 2, // 0.50
	Weak = 3,     // 0.25
	None = 4,     // 0.00
};

/// An association is the degree of certainty that two detections are related
typedef Certainty Association;

/**
 * If the strengths of two associations are to be combined, this function will compute the
 * resulting association. Using the numerical value of associations, the formula is
 * 1 - (1 - a1) * (1 - a2), rounded to the nearest association.
 */
Association AddAssociation(Association a1, Association a2);

/**
 * If an association is to be the composite of two associations, this function will compute the
 * resulting association. Using the numerical value of associations, the formula is
 * a1 * a2, rounded to the nearest association.
 */
Association MultiplyAssociation(Association a1, Association a2);

/// Forward declare scanners so they can be friends
class RegistryScanner;
class ProcessScanner;
class FileScanner; 

class DetectionNetwork;

/**
 * A ScanNode is the core unit of BLUESPAWN's scan functionality. Each detection is converted to a 
 * ScanNode. From there, each scan node identifies other detections related to its detection. These
 * detections and associations between them will form a web/graph of detections, which is used to
 * identify as much malicious activity as possible.
 */
class ScanNode {

	/// A mapping of scan nodes to their association with the current node.
	std::map<ScanNode, Association> associations;

	/// The detection referenced by the scan node
	Detection detection;

	/// The degree of certainty that the detection referenced by this scan node is malicious
	/// Note that this ignores all associations
	Certainty certainty;

	/// The degree of certainty that the detection referenced by this scan node is malicious
	/// Note that this is calculated only based on associations
	Certainty cAssociativeCertainty;

	/// Indicates whether cAssociativeCertainty has gone stale and must be recalculated
	bool bAssociativeStale;

	/// Allow RegistryScanner, FileScanner, and ProcessScanner access to private variables
	friend class RegistryScanner;
	friend class FileScanner;
	friend class ProcessScanner;
	
	friend class DetectionNetwork;

	void AddAssociation(const ScanNode& node, Association strength);

public:
	ScanNode(const Detection& detection);

	const std::map<ScanNode, Association>& GetAssociations();

	Certainty GetCertainty();

	bool operator==(const ScanNode& node) const;
	bool operator<(const ScanNode& node) const;
};

// Forward declare DetectionCollector so that it can be a friend;
class DetectionCollector;

/**
 * Represents a network of related ScanNode objects
 */
class DetectionNetwork {
private:
	
	std::vector<ScanNode> nodes;

	void GrowNetwork();

	friend class DetectionCollector;

	DetectionNetwork(std::vector<ScanNode>&& nodes);

public:
	DetectionNetwork(const ScanNode& node);

	bool IntersectsNetwork(const DetectionNetwork& network);

	DetectionNetwork MergeNetworks(const DetectionNetwork& network) const;
};