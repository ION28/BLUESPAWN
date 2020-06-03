#pragma once


#include <string>
#include <functional>
#include <memory>
#include <unordered_map>
#include <libgen.h>

#include "hunt/HuntInfo.h"
#include "util/filesystem/FileSystem.h"
#include "common/StringUtils.h"
#include "common/Utils.h"

enum class DetectionType {
	File,
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
	std::string wsFileName;
	std::string wsFilePath;
	std::string md5;
	std::string sha1;
	std::string sha256;
	std::string created;
	std::string modified;
	std::string accessed;
	FileSystem::File fFile;
	FILE_DETECTION(const FileSystem::File f) : 
		DETECTION{ DetectionType::File },
		wsFilePath{ f.GetFilePath() }, 
		fFile{ f } {
		char buffer[PATH_MAX + 1];
		strncpy(buffer, wsFilePath.c_str(), PATH_MAX + 1);
		wsFileName = std::string(basename(buffer));
		if (f.GetMD5Hash()) {
			md5 = f.GetMD5Hash().value();
		}
		if (f.GetSHA1Hash()) {
			sha1 = f.GetSHA1Hash().value();
		}
		if (f.GetSHA256Hash()) {
			sha256 = f.GetSHA256Hash().value();
		}
		if (f.GetCreationTime()) {
			created = FormatStatTime(f.GetCreationTime().value()); //TODO: work on filetime conversion
		}
		if (f.GetModifiedTime()) {
			modified = FormatStatTime(f.GetModifiedTime().value());
		}
		if (f.GetAccessTime()) {
			accessed = FormatStatTime(f.GetAccessTime().value());
		}
	}
};
typedef std::function<void(std::shared_ptr<FILE_DETECTION>)> DetectFile;

/// A struct containing information about a service identified in a hunt
struct SERVICE_DETECTION : public DETECTION {
	std::string wsServiceName;
	std::string wsServiceExecutablePath;
	std::string wsServiceDll;
	int ServicePID;
	SERVICE_DETECTION(const std::string& wsServiceName, const std::string& wsServiceExecutablePath, 
		const std::string& wsServiceDll, const int& ServicePID) :
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
	std::string wsImagePath;
	std::string wsCmdline;
	int PID;
	unsigned int method;
	void* lpAllocationBase;
	unsigned int dwAllocationSize;
	char AllocationStart[512];      // This member is intended to be used for signaturing purposes
	PROCESS_DETECTION(const std::string& wsImagePath, const std::string& wsCmdLine, const int& PID,
		const void*& lpAllocationBase, const unsigned int& dwAllocationSize, const unsigned int& method) :
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
	std::string timeCreated;
	std::string channel;
	std::string rawXML;
	std::unordered_map<std::string, std::string> params;
	
	EVENT_DETECTION(unsigned int eventID, unsigned int eventRecordID, std::string timeCreated, std::string channel, std::string rawXML) :
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