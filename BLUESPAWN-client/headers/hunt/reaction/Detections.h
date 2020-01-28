#pragma once

#include <Windows.h>

#include <string>
#include <functional>
#include <memory>

#include "hunt/HuntInfo.h"

enum class DetectionType {
	File,
	Registry,
	Service,
	Process,
	Event
};

struct DETECTION {
	DetectionType Type;
	DETECTION(DetectionType Type) : Type{ Type }{}
};

/// A struct containing information about a file identified in a hunt
/// Note that the hash will have to be manually set.
struct FILE_DETECTION : public DETECTION {
	std::wstring wsFileName;
	BYTE hash[256];
	FILE_DETECTION(const std::wstring& wsFileName) : 
		DETECTION{ DetectionType::File },
		wsFileName{ wsFileName },
		hash{}{}
};
typedef std::function<void(std::shared_ptr<FILE_DETECTION>)> DetectFile;

/// A struct containing information about a registry key value identified in a hunt
struct REGISTRY_DETECTION : public DETECTION {
	std::wstring wsRegistryKeyPath;
	std::wstring wsRegistryKeyValue;
	BYTE* contents;
	REGISTRY_DETECTION(const std::wstring& wsRegistryKeyPath, const std::wstring& wsRegistryKeyValue, BYTE* contents) :
		DETECTION{ DetectionType::Registry },
		wsRegistryKeyPath{ wsRegistryKeyPath },
		wsRegistryKeyValue{ wsRegistryKeyValue },
		contents{ contents }{}
};
typedef std::function<void(std::shared_ptr<REGISTRY_DETECTION>)> DetectRegistry;

/// A struct containing information about a service identified in a hunt
struct SERVICE_DETECTION : public DETECTION {
	std::wstring wsServiceName;
	std::wstring wsServiceExecutablePath;
	std::wstring wsServiceDll;
	int ServicePID;
	SERVICE_DETECTION(const std::wstring& wsServiceName, const std::wstring& wsServiceExecutablePath, 
		const std::wstring& wsServiceDll, const int& ServicePID) :
		DETECTION{ DetectionType::Service },
		wsServiceName{ wsServiceName },
		wsServiceExecutablePath{ wsServiceExecutablePath },
		wsServiceDll{ wsServiceDll },
		ServicePID{ ServicePID }{}
};
typedef std::function<void(std::shared_ptr<SERVICE_DETECTION>)> DetectService;

enum class ProcessDetectionMethod {
	NotImageBacked,
	BackingImageMismatch,
	NotInLoader,
	NotSigned,
	Other
};

/// A struct containing information about a process identified in a hunt
/// Note that the AllocationStart must be filled in manually
struct PROCESS_DETECTION : public DETECTION {
	std::wstring wsImageName;
	std::wstring wsImagePath;
	std::wstring wsCmdline;
	int PID;
	int TID;
	ProcessDetectionMethod method;
	BYTE AllocationStart[512];      // This member is intended to be used for signaturing purposes
	PROCESS_DETECTION(const std::wstring& wsImageName, const std::wstring& wsImagePath, const std::wstring& wsCmdLine,
		const int& PID, const int& TID, ProcessDetectionMethod method) :
		DETECTION{ DetectionType::Process },
		wsImageName{ wsImageName },
		wsImagePath{ wsCmdLine },
		PID{ PID },
		TID{ TID },
		method{ method },
		AllocationStart{}{}
};
typedef std::function<void(std::shared_ptr<PROCESS_DETECTION>)> DetectProcess;

enum class ServiceType {
	kernelModeDriver,
	userModeService
};

enum class ServiceStartType {
	systemStart,
	autoStart,
	demandStart
};

/// A struct containing information about a event identified in a hunt
struct EVENT_DETECTION : public DETECTION {
	unsigned int eventID;
	unsigned int eventRecordID;
	std::wstring timeCreated;
	std::wstring channel;
	std::wstring rawXML;
	std::unordered_map<std::wstring, std::wstring> params;
	
	EVENT_DETECTION(unsigned int eventID, unsigned int eventRecordID, std::wstring timeCreated, std::wstring channel, std::wstring rawXML) :
		DETECTION{ DetectionType::Event },
		eventID{ eventID },
		eventRecordID{ eventRecordID },
		timeCreated{ timeCreated },
		channel{ channel },
		rawXML{ rawXML }{}
};
typedef std::function<void(std::shared_ptr<EVENT_DETECTION>)> DetectEvent;

typedef std::function<void(const HuntInfo&)> HuntStart;
typedef std::function<void()> HuntEnd;