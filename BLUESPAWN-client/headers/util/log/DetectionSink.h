#pragma once

#include <Windows.h>

#include "scan/Detections.h"

enum class RecordType {
	
	/**
	 * Detections will be sent to the DetectionSink with PreScan every time a new Detection object
	 * is sent to the DetectionRegister. This will occur before any de-duplication or scans. There
	 * are expected to be a number of false positives of type PreScan
	 */
	PreScan,

	/**
	 * Detections will be sent to the DetectionSink with PostScan every time a Detection is scanned.
	 * This may be triggered multiple times for the same detection if a duplicate exists and causes the
	 * non-associative certainty to change. For duplicates where the non-associative certainty does
	 * not change, this will not be triggered.
	 */
	PostScan
};

class DetectionSink {
public:

	/**
	 * Records a detection to the sink. This may be recorded before the detection has been scanned or
	 * immediately after the scan. If all scans have not yet been finished, there may be associations 
	 * between detections not yet discovered. Be sure to acquire appropriate mutices before accessing 
	 * fields of the detection in implementations of this interface. Note: callers of this function
	 * must not hold either of the CriticalSections of the detection, or else a deadlock may arise.
	 *
	 * @param detection The detection to record
	 * @param type The type of record this is, either PreScan or PostScan
	 */
	virtual void RecordDetection(
		IN CONST std::shared_ptr<Detection>& detection,
		IN RecordType type
	) = 0;

	/**
	 * Records an association between two detections. If an association between the two already exists,
	 * then this represents a second assocation between the two, which should be added to the pre-existing
	 * association. 
	 *
	 * @param first The first detection in the assocation. This detection's ID will be lower than the second's.
	 * @param second The second detection in the association.
	 * @param strength The strength of the connection
	 */
	virtual void RecordAssociation(
		IN CONST std::shared_ptr<Detection>& first,
		IN CONST std::shared_ptr<Detection>& second,
		IN CONST Association& strength
	) = 0;

	/**
	 * Updates the raw and combined certainty values associated with a detection
	 *
	 * @param detection The detection to update
	 */
	virtual void UpdateCertainty(
		IN CONST std::shared_ptr<Detection>& detection
	) = 0;
};