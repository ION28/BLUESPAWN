#pragma once
#include <Windows.h>

#include <vector>
#include <string>

#include "hunt/HuntInfo.h"

#include "Detections.h"

/**
 * A container class for handling reactions to various types of detections.
 * This class will usually be used by instantiating one of more subclass of Reaction and
 * combining them to create the desired reaction. Addition reactions for certain types of 
 * detections can be added with the AddXXXXXReaction functions.
 */
class Reaction {
protected: 
	/// Handlers for detections
	std::vector<DetectFile> vFileReactions;
	std::vector<DetectRegistry> vRegistryReactions;
	std::vector<DetectService> vServiceReactions;
	std::vector<DetectProcess> vProcessReactions;
	std::vector<DetectEvent> vEventReactions;
	
	/// Handlers for startting and beginning hunts
	std::vector<HuntStart> vStartHuntProcs;
	std::vector<HuntEnd> vEndHuntProcs;

public: 
	/// These functions handle the beginning and end of hunts
	void BeginHunt(const HuntInfo& info);
	void EndHunt();

	/// These functions handle the identification of a detection by calling all of the associated handlers
	void FileIdentified(std::shared_ptr<FILE_DETECTION>);
	void RegistryKeyIdentified(std::shared_ptr<REGISTRY_DETECTION>);
	void ProcessIdentified(std::shared_ptr<PROCESS_DETECTION>);
	void ServiceIdentified(std::shared_ptr<SERVICE_DETECTION>);
	void EventIdentified(std::shared_ptr<EVENT_DETECTION>);

	/// These functions add handlers for beginning and ending hunts
	void AddHuntBegin(HuntStart handler);
	void AddHuntEnd(HuntEnd handler);

	/// These functions add handlers for detections
	void AddFileReaction(DetectFile handler);
	void AddRegistryReaction(DetectRegistry handler);
	void AddProcessReaction(DetectProcess handler);
	void AddServiceReaction(DetectService handler);
	void AddEventReaction(DetectEvent handler);

	/// Merges the given reaction into the current reaction
	Reaction& Combine(const Reaction& reaction);
	Reaction& Combine(Reaction&& reaction);
};