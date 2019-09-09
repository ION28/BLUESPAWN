#pragma once
#include <Windows.h>

#include "configuration/Registry.h"

#include <vector>

/// A struct containing information about a file identified in a hunt
typedef struct _FILE_DETECTION {
	std::wstring wsFileName;
	BYTE hash[256];
} FILE_DETECTION;
typedef void(*DetectFile)(FILE_DETECTION*);

/// A struct containing information about a registry key value identified in a hunt
typedef struct _REGISTRY_DETECTION {
	std::wstring wsRegistryKeyPath;
	std::wstring wsRegistryKeyValue;
	BYTE* contents;
} REGISTRY_DETECTION;
typedef void(*DetectRegistry)(REGISTRY_DETECTION*);

/// A struct containing information about a service identified in a hunt
typedef struct _SERVICE_DETECTION {
	std::wstring wsServiceName;
	std::wstring wsServiceExecutablePath;
	std::wstring wsServiceDll;
	int ServicePID;
} SERVICE_DETECTION;
typedef void(*DetectService)(SERVICE_DETECTION*);

enum ProcessDetectionMethod {
	NotImageBacked,
	BackingImageMismatch,
	NotInLoader,
	NotSigned
};

/// A struct containing information about a process identified in a hunt
typedef struct _PROCESS_DETECTION {
	std::wstring wsImageName;
	std::wstring wsImagePath;
	std::wstring wsCmdline;
	int PID;
	int TID;
	ProcessDetectionMethod method;
	BYTE AllocationStart[512];
} PROCESS_DETECTION;
typedef void(*DetectProcess)(PROCESS_DETECTION*);

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

public: 
	/// These functions handle the identification of a detection by calling all of the associated handlers
	void FileIdentified(FILE_DETECTION*);
	void RegistryKeyIdentified(REGISTRY_DETECTION*);
	void ProcessIdentified(PROCESS_DETECTION*);
	void ServiceIdentified(SERVICE_DETECTION*);

	/// These functions add handlers for detections
	void AddFileReaction(DetectFile handler);
	void AddRegistryReaction(DetectRegistry handler);
	void AddProcessReaction(DetectProcess handler);
	void AddServiceReaction(DetectService handler);

	/// Combines two reactions, returning a new reaction object that has the handlers present in both
	Reaction Combine(const Reaction& reaction);
	Reaction Combine(Reaction&& reaction);
};