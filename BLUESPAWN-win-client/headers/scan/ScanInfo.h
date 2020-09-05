#pragma once

#include <windows.h>

#include <memory>
#include <vector>
#include <map>
#include <atomic>

class Scanner;
class Detection;

/// Forward declare template specializaiton for hashing reference wrappers for detections
template<>
struct std::hash<std::shared_ptr<Detection>>;

#include "util/wrappers.hpp"

/// Represents the degree of certainty that a detection is malicious
class Certainty {

	/// A double holding a number between 0 and 1, indicating how strongly the referenced detection
	/// is believed to be malicious, with 1 being the most certain that it is malicious
	double confidence;

public:

	/// Define static certainty values
	const static Certainty Certain;  // 1.00
	const static Certainty Strong;   // 0.75
	const static Certainty Moderate; // 0.50
	const static Certainty Weak;     // 0.25
	const static Certainty None;     // 0.00

	Certainty(double value);
	operator double() const;

	/**
	 * If the strengths of two associations are to be combined, this function will compute the
	 * resulting association. Using the numerical value of associations, the formula is
	 * 1 - (1 - a1) * (1 - a2).
	 */
	Certainty operator+(Certainty c) const;

	/**
	 * If an association is to be the composite of two associations, this function will compute the
	 * resulting association. Using the numerical value of associations, the formula is
	 * a1 * a2.
	 */
	Certainty operator*(Certainty c) const;

	/**
	 * Used for comparing between certainties. Note that is computes approximate comparisons rather
	 * than exact comparisons. Thus, any value within 0.125 of `confidence` is considered equal
	 */
	bool operator==(Certainty c) const;
	bool operator!=(Certainty c) const;
	bool operator<=(Certainty c) const;
	bool operator>=(Certainty c) const;

	// These functions use exact comparisons rather than approximate comparisons
	bool operator>(Certainty c) const;
	bool operator<(Certainty c) const;
};

/// An association is the degree of certainty that two detections are related
typedef Certainty Association;

/**
 * A ScanInfo is the core unit of BLUESPAWN's scan functionality. This records information
 * such as associations, resulting certainty from scans, and associative certainty.
 */
class ScanInfo {

	/// A mapping of detections to their association strength with the current node.
	std::unique_ptr<std::unordered_map<std::shared_ptr<Detection>, Association>> associations;

	/// The degree of certainty that the detection referenced by this scan node is malicious
	/// Note that this ignores all associations
	Certainty certainty;

	/// The degree of certainty that the detection referenced by this scan node is malicious
	/// Note that this is calculated only based on associations
	Certainty cAssociativeCertainty;

	/// Indicates whether cAssociativeCertainty has gone stale and must be recalculated
	bool bAssociativeStale;

	/// Guards access to `associations`
	CriticalSection hGuard;

	friend class DetectionRegister;
	friend class RegistryScanner;
	friend class FileScanner;
	friend class ProcessScanner;
	friend class MemoryScanner;
	friend class ServiceScanner;
	friend class Detection;

public:

	/**
	 * Constructs a new ScanInfo object
	 */
	ScanInfo();

	/**
	 * Gets a map of the associations of this node.
	 *
	 * @return The associations of this node
	 */
	std::unordered_map<std::shared_ptr<Detection>, Association> GetAssociations();

	/**
	 * Retrieves the certainty that the detection this is a part of is malicious. If any association has
	 * been added since the last call to GetCertainty, the associative certainty will be recalculated.
	 *
	 * @return The certainty that the detection this is a part of is malicious
	 */
	Certainty GetCertainty();

	/**
	 * Retrieves the certainty that the associated detection's data refers to something malicious. This function 
	 * ignores assocaitivity certainty.
	 *
	 * @return The certainty that the detection this is a part of is malicious
	 */
	Certainty GetIntrinsicCertainty();

	/**
	 * Sets the degree of certainty that the detection referenced by this scan node is malicious. This does not affect 
	 * the associative certainty of this ScanNode.
	 *
	 * @param certainty The value of certainty to be set
	 */
	void SetCertainty(
		IN CONST Certainty& certainty
	);

	/**
	 * Adds to the degree of certainty that the detection referenced by this scan node is malicious. This does not affect
	 * the associative certainty of this ScanNode.
	 *
	 * @param certainty The value of certainty to be added
	 */
	void AddCertainty(
		IN CONST Certainty& certainty
	);

	/**
	 * Implicit cast to a CRITICAL_SECTION pointer for use in synchronization functions
	 *
	 * @return hGuard
	 */
	operator LPCRITICAL_SECTION() const;

	/**
	 * Adds an association between this node and the given node with the given strength. Note that
	 * this only adds the association one way; node->AddAssociation(*this) must be called separately
	 * for the association to be bidirectional (as all associations should be).
	 *
	 * @param node The node to add an association to.
	 * @param strength The strength of the association between the two nodes
	 */
	void AddAssociation(
		IN CONST std::shared_ptr<Detection>& node,
		IN CONST Association& strength
	);
};