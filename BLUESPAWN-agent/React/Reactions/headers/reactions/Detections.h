#pragma once

#include <Windows.h>

#include <string>
#include <functional>

#include "hunts/HuntInfo.h"

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
struct FILE_DETECTION {
	DetectionType DetectionType;
	std::wstring wsFileName;
	BYTE hash[256];
};
typedef std::function<void(FILE_DETECTION*)> DetectFile;

/// A struct containing information about a registry key value identified in a hunt
struct REGISTRY_DETECTION {
	DetectionType DetectionType;
	std::wstring wsRegistryKeyPath;
	std::wstring wsRegistryKeyValue;
	BYTE* contents;
};
typedef std::function<void(REGISTRY_DETECTION*)> DetectRegistry;

/// A struct containing information about a service identified in a hunt
struct SERVICE_DETECTION {
	DetectionType DetectionType;
	std::wstring wsServiceName;
	std::wstring wsServiceExecutablePath;
	std::wstring wsServiceDll;
	int ServicePID;
};
typedef std::function<void(SERVICE_DETECTION*)> DetectService;

enum ProcessDetectionMethod {
	NotImageBacked,
	BackingImageMismatch,
	NotInLoader,
	NotSigned
};

/// A struct containing information about a process identified in a hunt
struct PROCESS_DETECTION {
	DetectionType DetectionType;
	std::wstring wsImageName;
	std::wstring wsImagePath;
	std::wstring wsCmdline;
	int PID;
	int TID;
	ProcessDetectionMethod method;
	BYTE AllocationStart[512];
};
typedef std::function<void(PROCESS_DETECTION*)> DetectProcess;

typedef std::function<void(const HuntInfo&)> HuntStart;
typedef std::function<void()> HuntEnd;