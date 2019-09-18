#pragma once
#include <Windows.h>

#include <vector>
#include <string>

#include "hunts/HuntInfo.h"

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
	
	/// Handlers for startting and beginning hunts
	std::vector<HuntStart> vStartHuntProcs;
	std::vector<HuntEnd> vEndHuntProcs;

public: 
	/// These functions handle the beginning and end of hunts
	void BeginHunt(const HuntInfo& info) const;
	void EndHunt() const;

	/// These functions handle the identification of a detection by calling all of the associated handlers
	void FileIdentified(FILE_DETECTION*) const;
	void RegistryKeyIdentified(REGISTRY_DETECTION*) const;
	void ProcessIdentified(PROCESS_DETECTION*) const;
	void ServiceIdentified(SERVICE_DETECTION*) const;

	/// These functions add handlers for beginning and ending hunts
	void AddHuntBegin(HuntStart handler);
	void AddHuntEnd(HuntEnd handler);

	/// These functions add handlers for detections
	void AddFileReaction(DetectFile handler);
	void AddRegistryReaction(DetectRegistry handler);
	void AddProcessReaction(DetectProcess handler);
	void AddServiceReaction(DetectService handler);

	/// Combines two reactions, returning a new reaction object that has the handlers present in both
	Reaction Combine(const Reaction& reaction) const;
	Reaction Combine(Reaction&& reaction) const;
};