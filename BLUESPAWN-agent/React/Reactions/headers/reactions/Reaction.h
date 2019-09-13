#pragma once
#include <Windows.h>

#include "configuration/Registry.h"

#include <vector>

enum class DetectionType {
	File,
	Registry,
	Service,
	Process
};

struct DETECTION {
	DetectionType DetectionType;
};

/// A struct containing information about a file identified in a hunt
struct FILE_DETECTION : public DETECTION {
	std::wstring wsFileName;
	BYTE hash[256];
};
typedef void(*DetectFile)(FILE_DETECTION*);

/// A struct containing information about a registry key value identified in a hunt
typedef struct REGISTRY_DETECTION : public DETECTION {
	std::wstring wsRegistryKeyPath;
	std::wstring wsRegistryKeyValue;
	BYTE* contents;
};
typedef void(*DetectRegistry)(REGISTRY_DETECTION*);

/// A struct containing information about a service identified in a hunt
typedef struct SERVICE_DETECTION : public DETECTION {
	std::wstring wsServiceName;
	std::wstring wsServiceExecutablePath;
	std::wstring wsServiceDll;
	int ServicePID;
};
typedef void(*DetectService)(SERVICE_DETECTION*);

enum ProcessDetectionMethod {
	NotImageBacked,
	BackingImageMismatch,
	NotInLoader,
	NotSigned
};

/// A struct containing information about a process identified in a hunt
typedef struct PROCESS_DETECTION : public DETECTION {
	std::wstring wsImageName;
	std::wstring wsImagePath;
	std::wstring wsCmdline;
	int PID;
	int TID;
	ProcessDetectionMethod method;
	BYTE AllocationStart[512];
};
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