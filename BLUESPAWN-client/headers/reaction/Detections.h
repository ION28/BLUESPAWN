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
	Event,
	Other
};

class Hunt;

enum class DetectionSource {
	Association, Hunt
};

struct DETECTION {
	DetectionType Type;
	std::vector<DWORD> AssociatedDetections;
	DWORD dwID;
	DetectionSource source;
	std::optional<std::wstring> hunt;
	DETECTION(DetectionType Type, const std::wstring& hunt) : 
		Type{ Type },
		source{ DetectionSource::Hunt },
		hunt{ hunt }{}

	DETECTION(DetectionType Type) :
		Type{ Type },
		source{ DetectionSource::Association },
		hunt{ std::nullopt }{}
};
typedef std::shared_ptr<DETECTION> Detection;

/// A struct containing information about a file identified in a hunt
/// Note that the hash will have to be manually set.
struct FILE_DETECTION : public DETECTION {
	std::wstring wsFileName;
	std::wstring wsFilePath;
	std::string hash;
	FileSystem::File file;
	FILE_DETECTION(const std::wstring& wsFilePath) :
		DETECTION{ DetectionType::File },
		wsFilePath{ wsFilePath },
		file{ wsFilePath },
		hash{}{
		wsFileName = ToLowerCaseW(wsFilePath.substr(wsFilePath.find_last_of(L"\\/") + 1));
	}
	FILE_DETECTION(const std::wstring& wsFilePath, const std::wstring& hunt) :
		DETECTION{ DetectionType::File, hunt },
		wsFilePath{ wsFilePath },
		file{ wsFilePath },
		hash{}{
		wsFileName = ToLowerCaseW(wsFilePath.substr(wsFilePath.find_last_of(L"\\/") + 1));
	}
	FILE_DETECTION(const FileSystem::File& file) :
		DETECTION{ DetectionType::File },
		wsFilePath{ file.GetFilePath() },
		file{ file },
		hash{}{
		wsFileName = ToLowerCaseW(wsFilePath.substr(wsFilePath.find_last_of(L"\\/") + 1));
	}
	FILE_DETECTION(const FileSystem::File& file, const std::wstring& hunt) :
		DETECTION{ DetectionType::File, hunt },
		wsFilePath{ file.GetFilePath() },
		file{ file },
		hash{}{
		wsFileName = ToLowerCaseW(wsFilePath.substr(wsFilePath.find_last_of(L"\\/") + 1));
	}
};
typedef std::shared_ptr<FILE_DETECTION> FileDetection;
typedef std::function<void(std::shared_ptr<FILE_DETECTION>)> DetectFile;

enum class RegistryDetectionType {
	CommandReference, // The associated value is either a REG_SZ or REG_EXPAND_SZ that references a command used to run program
	FileReference,    // The associated value is either a REG_SZ or REG_EXPAND_SZ that references a file
	FolderReference,  // The associated value is either a REG_SZ or REG_EXPAND_SZ that references a folder
	PipeReference,    // The associated value is either a REG_SZ that references a named pipe
	ShareReference,   // The associated value is either a REG_SZ that references a share
	UserReference,    // The associated value is either a REG_SZ that references a user
	Configuration,    // The associated value references a configuration for the operating system
	Association       // The associated value is assumed malicious due to association with other malicious detections
};

/// A struct containing information about a registry key value identified in a hunt
struct REGISTRY_DETECTION : public DETECTION {
	Registry::RegistryValue value;
	RegistryDetectionType type;
	bool multitype;
	REGISTRY_DETECTION(const Registry::RegistryValue& value, RegistryDetectionType type = RegistryDetectionType::Association) :
		DETECTION{ DetectionType::Registry },
		type{ type },
		multitype{ false },
		value{ value }{}

	REGISTRY_DETECTION(const Registry::RegistryValue& value, const std::wstring& hunt, 
					   RegistryDetectionType type = RegistryDetectionType::Configuration,
					   bool multitype = false) :
		DETECTION{ DetectionType::Registry, hunt },
		type{ type },
		multitype{ multitype },
		value{ value }{}
};
typedef std::shared_ptr<REGISTRY_DETECTION> RegistryDetection;
typedef std::function<void(std::shared_ptr<REGISTRY_DETECTION>)> DetectRegistry;

/// A struct containing information about a service identified in a hunt
struct SERVICE_DETECTION : public DETECTION {
	std::wstring wsServiceName;
	std::wstring wsServiceExecutablePath;
	std::optional<std::wstring> wsServiceDll;
	SERVICE_DETECTION(const std::wstring& wsServiceName, const std::wstring& wsServiceExecutablePath) :
		DETECTION{ DetectionType::Service },
		wsServiceName{ wsServiceName },
		wsServiceExecutablePath{ wsServiceExecutablePath }{}
};
typedef std::shared_ptr<SERVICE_DETECTION> ServiceDetection;
typedef std::function<void(std::shared_ptr<SERVICE_DETECTION>)> DetectService;

enum class ProcessDetectionMethod {
	Replaced       = 1,
	HeaderModified = 2,
	Detached       = 4,
	Hooked         = 8,
	Implanted      = 16,
	File           = 32,
	Other          = 64
};

struct PROCESS_DETECTION : public DETECTION {
	std::wstring wsImagePath;
	std::wstring wsCmdline;
	int PID;
	DWORD method;
	LPVOID lpAllocationBase;
	DWORD dwAllocationSize;
	PROCESS_DETECTION(const std::wstring& wsImagePath, const std::wstring& wsCmdLine, const int& PID,
		const LPVOID& lpAllocationBase, const DWORD& dwAllocationSize, const DWORD& method) :
		DETECTION{ DetectionType::Process },
		wsImagePath{ wsImagePath },
		wsCmdline{ wsCmdLine },
		PID{ PID },
		method{ method },
		lpAllocationBase{ lpAllocationBase },
		dwAllocationSize{ dwAllocationSize }{}
};
typedef std::shared_ptr<PROCESS_DETECTION> ProcessDetection;
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
	
	EVENT_DETECTION(unsigned int eventID, unsigned int eventRecordID, const std::wstring& timeCreated, 
					const std::wstring& channel, const std::wstring& rawXML) :
		DETECTION{ DetectionType::Event },
		eventID{ eventID },
		eventRecordID{ eventRecordID },
		timeCreated{ timeCreated },
		channel{ channel },
		rawXML{ rawXML }{}
};
typedef std::shared_ptr<EVENT_DETECTION> EventDetection;
typedef std::function<void(std::shared_ptr<EVENT_DETECTION>)> DetectEvent;

struct OTHER_DETECTION : public DETECTION {
	std::wstring type;
	std::map<std::wstring, std::wstring> params;

	OTHER_DETECTION(const std::wstring& type, const std::map<std::wstring, std::wstring>& params) : 
		DETECTION{ DetectionType::Other },
		type{ type },
		params{ params }{}
};
typedef std::shared_ptr<OTHER_DETECTION> OtherDetection;
typedef std::function<void(std::shared_ptr<OTHER_DETECTION>)> DetectOther;


typedef std::function<void(const HuntInfo&)> HuntStart;
typedef std::function<void()> HuntEnd;