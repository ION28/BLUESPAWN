#pragma once

#include <Windows.h>

#include <string>
#include <functional>
#include <memory>

#include "hunt/HuntInfo.h"
#include "util/configurations/RegistryValue.h"
#include "util/filesystem/FileSystem.h"
#include <common\StringUtils.h>

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
struct FILE_DETECTION : public DETECTION {
	std::wstring wsFileName;
	std::wstring wsFilePath;
	std::wstring md5;
	std::wstring sha1;
	std::wstring sha256;
	FILE_DETECTION(const FileSystem::File f) : 
		DETECTION{ DetectionType::File },
		wsFilePath{ f.GetFilePath() }{
		wsFileName = ToLowerCaseW(wsFilePath.substr(wsFilePath.find_last_of(L"\\/") + 1));
		if (f.GetMD5Hash()) {
			md5 = f.GetMD5Hash().value();
		}
		if (f.GetSHA1Hash()) {
			sha1 = f.GetSHA1Hash().value();
		}
		if (f.GetSHA256Hash()) {
			sha256 = f.GetSHA256Hash().value();
		}
	}
};
typedef std::function<void(std::shared_ptr<FILE_DETECTION>)> DetectFile;

/// A struct containing information about a registry key value identified in a hunt
struct REGISTRY_DETECTION : public DETECTION {
	Registry::RegistryValue value;
	REGISTRY_DETECTION(const Registry::RegistryValue& value) :
		DETECTION{ DetectionType::Registry },
		value{ value }{}
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
	Replaced       = 1,
	HeaderModified = 2,
	Detached       = 4,
	Hooked         = 8,
	Implanted      = 16,
	Other          = 32
};

struct PROCESS_DETECTION : public DETECTION {
	std::wstring wsImagePath;
	std::wstring wsCmdline;
	int PID;
	DWORD method;
	LPVOID lpAllocationBase;
	DWORD dwAllocationSize;
	BYTE AllocationStart[512];      // This member is intended to be used for signaturing purposes
	PROCESS_DETECTION(const std::wstring& wsImagePath, const std::wstring& wsCmdLine, const int& PID,
		const LPVOID& lpAllocationBase, const DWORD& dwAllocationSize, const DWORD& method) :
		DETECTION{ DetectionType::Process },
		wsImagePath{ wsImagePath },
		wsCmdline{ wsCmdLine },
		PID{ PID },
		method{ method },
		lpAllocationBase{ lpAllocationBase },
		dwAllocationSize{ dwAllocationSize },
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