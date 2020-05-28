#pragma once

#include "reaction/Detections.h"

#include <memory>
#include <vector>
#include <map>
#include <atomic>

/// Represents the degree of certainty that a detection is malicious
class Certainty {
	double confidence;

public:

	const static Certainty Certain;
	const static Certainty Strong;
	const static Certainty Moderate;
	const static Certainty Weak;
	const static Certainty None;

	Certainty(double value);
	operator double();

	/**
	 * If the strengths of two associations are to be combined, this function will compute the
	 * resulting association. Using the numerical value of associations, the formula is
	 * 1 - (1 - a1) * (1 - a2).
	 */
	Certainty operator+(Certainty c);

	/**
	 * If an association is to be the composite of two associations, this function will compute the
	 * resulting association. Using the numerical value of associations, the formula is
	 * a1 * a2.
	 */
	Certainty operator*(Certainty c);

	/**
	 * Used for comparing between certainties. Note that is computes approximate comparisons rather
	 * than exact comparisons. Thus, any value within 0.125 of `confidence` is considered equal
	 */
	bool operator==(Certainty c);
	bool operator!=(Certainty c);
	bool operator<=(Certainty c);
	bool operator>=(Certainty c);

	// These functions use exact comparisons rather than approximate comparisons
	bool operator>(Certainty c);
	bool operator<(Certainty c);
};

/// An association is the degree of certainty that two detections are related
typedef Certainty Association;

/// Forward declare scanners and DetectionNetwork so they can be friends
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

	static std::atomic<DWORD> IDCounter;

	/// A mapping of scan nodes to their association with the current node.
	std::map<std::shared_ptr<ScanNode>, Association> associations;

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

	/// A unique identifier for this node
	DWORD dwID;

	/// Allow RegistryScanner, FileScanner, ProcessScanner, and DetectionNetwork access to private variables
	friend class RegistryScanner;
	friend class FileScanner;
	friend class ProcessScanner;
	friend class DetectionNetwork;

	void AddAssociation(const std::shared_ptr<ScanNode>& node, Association strength);

public:
	ScanNode(const Detection& detection);

	static const std::map<std::shared_ptr<ScanNode>, Association>& GetAssociations(const std::shared_ptr<ScanNode>& node);

	Certainty GetCertainty();
	DWORD GetID();


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
	
	std::vector<std::shared_ptr<ScanNode>> nodes;

	void GrowNetwork();

	friend class DetectionCollector;

	DetectionNetwork(std::vector<std::shared_ptr<ScanNode>>&& nodes);

public:
	DetectionNetwork(const std::shared_ptr<ScanNode>& node);

	bool IntersectsNetwork(const DetectionNetwork& network);

	DetectionNetwork MergeNetworks(const DetectionNetwork& network) const;
};