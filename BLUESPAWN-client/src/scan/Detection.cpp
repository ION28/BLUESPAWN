#include "scan/Detections.h"

#include "util/processes/ProcessUtils.h"

#include "common/StringUtils.h"
#include "common/Utils.h"

ProcessDetectionData ProcessDetectionData::CreateImageDetectionData(
	IN DWORD PID,
	IN CONST std::wstring& ProcessName,
	IN CONST std::wstring& ImageName,
	IN CONST std::optional<PVOID64>& BaseAddress OPTIONAL,
	IN CONST std::optional<DWORD>& MemorySize OPTIONAL,
	IN CONST std::optional<std::wstring>& ProcessPath OPTIONAL,
	IN CONST std::optional<std::wstring>& ProcessCommand OPTIONAL,
	IN std::unique_ptr<ProcessDetectionData>&& ParentProcess OPTIONAL
){
	HandleWrapper hProcess{ OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, PID) };
	if(hProcess){
		return CreateImageDetectionData(hProcess, ProcessName, ImageName, BaseAddress, MemorySize, ProcessPath,
										ProcessCommand, std::move(ParentProcess));
	} else {
		return ProcessDetectionData{
			ProcessDetectionType::MaliciousImage,
			PID,                      // PID
			std::nullopt,             // TID
			std::nullopt,             // ProcessHandle
			ProcessName,              // ProcessName
			ProcessPath,              // ProcessPath
			ProcessCommand,           // ProcessCommand
			std::move(ParentProcess), // ParentProcess
			BaseAddress,              // BaseAddress
			MemorySize,               // MemorySize
			ImageName                 // ImageName
		};
	}
}

ProcessDetectionData ProcessDetectionData::CreateImageDetectionData(
	IN CONST HandleWrapper& ProcessHandle,
	IN CONST std::wstring& ProcessName,
	IN CONST std::wstring& ImageName,
	IN CONST std::optional<PVOID64>& BaseAddress OPTIONAL,
	IN CONST std::optional<DWORD>& MemorySize OPTIONAL,
	IN CONST std::optional<std::wstring>& ProcessPath OPTIONAL,
	IN CONST std::optional<std::wstring>& ProcessCommand OPTIONAL,
	IN std::unique_ptr<ProcessDetectionData>&& ParentProcess OPTIONAL
){
	auto addr{ BaseAddress ? *BaseAddress : GetModuleAddress(ProcessHandle, ImageName) };

	return ProcessDetectionData{
		ProcessDetectionType::MaliciousImage,                                   // type
		GetProcessId(ProcessHandle),                                            // PID
		std::nullopt,                                                           // TID
		ProcessHandle,                                                          // ProcessHandle
		ProcessName,                                                            // ProcessName
		ProcessPath ? ProcessPath : GetProcessImage(ProcessHandle),             // ProcessPath
		ProcessCommand ? ProcessCommand : GetProcessCommandline(ProcessHandle), // ProcessCommand
		std::move(ParentProcess),                                               // ParentProcess
		addr,                                                                   // BaseAddress
		MemorySize ? MemorySize : GetRegionSize(ProcessHandle, addr),           // MemorySize
		ImageName                                                               // ImageName
	};
}

ProcessDetectionData ProcessDetectionData::CreateProcessDetectionData(
	IN DWORD PID,
	IN CONST std::wstring& ProcessName,
	IN CONST std::optional<std::wstring>& ProcessPath OPTIONAL,
	IN CONST std::optional<std::wstring>& ProcessCommand OPTIONAL,
	IN std::unique_ptr<ProcessDetectionData>&& ParentProcess OPTIONAL
){
	HandleWrapper hProcess{ OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, PID) };
	if(hProcess){
		return CreateProcessDetectionData(hProcess, ProcessName, ProcessPath, ProcessCommand, std::move(ParentProcess));
	} else{
		return ProcessDetectionData{
			ProcessDetectionType::MaliciousProcess,
			PID,                      // PID
			std::nullopt,             // TID
			std::nullopt,             // ProcessHandle
			ProcessName,              // ProcessName
			ProcessPath,              // ProcessPath
			ProcessCommand,           // ProcessCommand
			std::move(ParentProcess), // ParentProcess
			std::nullopt,             // BaseAddress
			std::nullopt,             // MemorySize
			std::nullopt              // ImageName
		};
	}
}

ProcessDetectionData ProcessDetectionData::CreateProcessDetectionData(
	IN CONST HandleWrapper& ProcessHandle,
	IN CONST std::wstring& ProcessName,
	IN CONST std::optional<std::wstring>& ProcessPath OPTIONAL,
	IN CONST std::optional<std::wstring>& ProcessCommand OPTIONAL,
	IN std::unique_ptr<ProcessDetectionData>&& ParentProcess OPTIONAL
){
	return ProcessDetectionData{
		ProcessDetectionType::MaliciousProcess,                                 // type
		GetProcessId(ProcessHandle),                                            // PID
		std::nullopt,                                                           // TID
		ProcessHandle,                                                          // ProcessHandle
		ProcessName,                                                            // ProcessName
		ProcessPath ? ProcessPath : GetProcessImage(ProcessHandle),             // ProcessPath
		ProcessCommand ? ProcessCommand : GetProcessCommandline(ProcessHandle), // ProcessCommand
		std::move(ParentProcess),                                               // ParentProcess
		std::nullopt,                                                           // BaseAddress
		std::nullopt,                                                           // MemorySize
		std::nullopt                                                            // ImageName
	};
}

ProcessDetectionData ProcessDetectionData::CreateMemoryDetectionData(
	IN DWORD PID,
	IN CONST std::wstring& ProcessName,
	IN PVOID64 BaseAddress,
	IN DWORD MemorySize,
	IN CONST std::optional<std::wstring>& ImageName = std::nullopt OPTIONAL,
	IN CONST std::optional<std::wstring>& ProcessPath = std::nullopt OPTIONAL,
	IN CONST std::optional<std::wstring>& ProcessCommand = std::nullopt OPTIONAL,
	IN std::unique_ptr<ProcessDetectionData>&& ParentProcess = nullptr OPTIONAL
){
	HandleWrapper hProcess{ OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, PID) };
	if(hProcess){
		return CreateMemoryDetectionData(hProcess, ProcessName, BaseAddress, MemorySize, ImageName, ProcessPath,
										ProcessCommand, std::move(ParentProcess));
	} else{
		return ProcessDetectionData{
			ProcessDetectionType::MaliciousMemory,
			PID,                      // PID
			std::nullopt,             // TID
			std::nullopt,             // ProcessHandle
			ProcessName,              // ProcessName
			ProcessPath,              // ProcessPath
			ProcessCommand,           // ProcessCommand
			std::move(ParentProcess), // ParentProcess
			BaseAddress,              // BaseAddress
			MemorySize,               // MemorySize
			ImageName                 // ImageName
		};
	}
}

ProcessDetectionData ProcessDetectionData::CreateMemoryDetectionData(
	IN CONST HandleWrapper& ProcessHandle,
	IN CONST std::wstring& ProcessName,
	IN PVOID64 BaseAddress,
	IN DWORD MemorySize,
	IN CONST std::optional<std::wstring>& ImageName = std::nullopt OPTIONAL,
	IN CONST std::optional<std::wstring>& ProcessPath = std::nullopt OPTIONAL,
	IN CONST std::optional<std::wstring>& ProcessCommand = std::nullopt OPTIONAL,
	IN std::unique_ptr<ProcessDetectionData>&& ParentProcess = nullptr OPTIONAL
){
	std::optional<std::wstring> image{ ImageName };
	if(!image){
		auto mapped{ GetMappedFile(ProcessHandle, BaseAddress) };
		if(mapped){
			image = mapped->GetFilePath();
		}
	}

	return ProcessDetectionData{
		ProcessDetectionType::MaliciousMemory,                                  // type
		GetProcessId(ProcessHandle),                                            // PID
		std::nullopt,                                                           // TID
		ProcessHandle,                                                          // ProcessHandle
		ProcessName,                                                            // ProcessName
		ProcessPath ? ProcessPath : GetProcessImage(ProcessHandle),             // ProcessPath
		ProcessCommand ? ProcessCommand : GetProcessCommandline(ProcessHandle), // ProcessCommand
		std::move(ParentProcess),                                               // ParentProcess
		BaseAddress,                                                            // BaseAddress
		MemorySize,                                                             // MemorySize
		image                                                                   // ImageName
	};
}

std::map<std::wstring, std::wstring> ProcessDetectionData::operator*() CONST {
	std::map<std::wstring, std::wstring> properties{
		{ L"Type", type == ProcessDetectionType::MaliciousImage ? L"Image" :
				   type == ProcessDetectionType::MaliciousMemory ? L"Memory" : L"Process"},
		{ L"Name", ProcessName },
		{ L"PID", std::to_wstring(PID) }
	};
	if(TID) properties.emplace(L"TID", *TID);
	if(ProcessPath) properties.emplace(L"Process Path", *ProcessPath);
	if(ProcessCommand) properties.emplace(L"Process Command", *ProcessCommand);
	if(ParentProcess) properties.emplace(L"Parent PID", (*ParentProcess)->PID);
	if(BaseAddress) properties.emplace(L"Base Address", *BaseAddress);
	if(MemorySize) properties.emplace(L"Memory Size", *MemorySize);
	if(ImageName) properties.emplace(L"Image Name", *ImageName);
	return properties;
}

size_t ProcessDetectionData::operator~() CONST {
	if(type == ProcessDetectionType::MaliciousProcess){
		return (static_cast<size_t>(PID) << 8) ^ std::hash<std::wstring>{}(ProcessName) ^
			(ProcessCommand ? std::hash<std::wstring>{}(*ProcessCommand) : 0) ^
			(ProcessPath ? std::hash<std::wstring>{}(*ProcessPath) : 0);
	} else{
		return (static_cast<size_t>(PID) << 8) ^ std::hash<std::wstring>{}(ProcessName) ^
			(ProcessCommand ? std::hash<std::wstring>{}(*ProcessCommand) : 0) ^
			(ProcessPath ? std::hash<std::wstring>{}(*ProcessPath) : 0) ^
			(BaseAddress ? reinterpret_cast<DWORD64>(*BaseAddress) * 75 + 0x12345: 0) ^
			(MemorySize ? *MemorySize * 75 + 0x98765 : 0);
	}
}

FileDetectionData::FileDetectionData(
	IN CONST FileSystem::File& file,
	IN CONST std::optional<YaraScanResult>& scan OPTIONAL
) : FileFound{ file.GetFileExists() },
	FilePath{ file.GetFilePath() },
	FileName{ FilePath.find(L"\\/") == std::wstring::npos ? FilePath : FilePath.substr(FilePath.find_last_of(L"\\/")) },
	FileExtension{ file.GetFileAttribs().extension },
	FileHandle{ file },
	HashInfo{
	    file.GetMD5Hash(),
		file.GetSHA1Hash(),
		file.GetSHA256Hash()
    },
	TimestampInfo{
	    file.GetAccessTime(),
	    file.GetCreationTime()
    },
	yara{ scan ? scan : 
	    (FileFound ? std::optional<YaraScanResult>(YaraScanner::GetInstance().ScanFile(file)) : std::nullopt) },
	FileSigned{ FileFound ? std::optional<bool>(file.GetFileSigned()) : std::nullopt },
	Signer{ FileSigned && *FileSigned ? file.GetCertificateIssuer() : std::nullopt }{
	if(FileExtension){
		Registry::RegistryKey FileExtClass{ HKEY_CLASSES_ROOT, *FileExtension };
		if(FileExtClass.Exists() && FileExtClass.ValueExists(L"")){
			FileType = FileExtClass.GetValue<std::wstring>(L"");
			if(FileType){
				Registry::RegistryKey FileClass{ HKEY_CLASSES_ROOT, *FileType };
				if(FileClass.Exists()){
					Registry::RegistryKey shell{ FileClass, L"shell\\open\\command" };
					auto command{ shell.GetValue<std::wstring>(L"") };
					if(command){
						Executor = StringReplaceW(*command, L"%1", FilePath);
					}
				}
			}
		}
	}
}

FileDetectionData::FileDetectionData(
	IN CONST std::wstring& path
) : FileDetectionData(FileSystem::File{ path }, std::nullopt){}

std::map<std::wstring, std::wstring> FileDetectionData::operator*() CONST {
	std::map<std::wstring, std::wstring> properties{
		{ L"Path", FilePath },
		{ L"Name", FileName },
		{ L"Exists", FileFound ? L"true" : L"false" },
	};
	if(FileExtension) properties.emplace(L"Extension", *FileExtension);
	if(FileType) properties.emplace(L"File Type", *FileType);
	if(Executor) properties.emplace(L"File Executor", *Executor);
	if(HashInfo.MD5) properties.emplace(L"MD5 Hash", *HashInfo.MD5);
	if(HashInfo.SHA1) properties.emplace(L"SHA1 Hash", *HashInfo.SHA1);
	if(HashInfo.SHA256) properties.emplace(L"SHA256 Hash", *HashInfo.SHA256);
	if(TimestampInfo.LastOpened) properties.emplace(L"Last Opened", FormatWindowsTime(*TimestampInfo.LastOpened));
	if(TimestampInfo.FileCreated) properties.emplace(L"Date Created", FormatWindowsTime(*TimestampInfo.FileCreated));
	if(yara){
		std::wstring malicious{};
		for(auto& mal : yara->vKnownBadRules){
			if(malicious.length()) malicious += L", ";
			malicious += mal;
		}
		std::wstring identifier{};
		for(auto& id : yara->vKnownBadRules){
			if(identifier.length()) identifier += L", ";
			identifier += id;
		}
		properties.emplace(L"Malicious Yara Rules", malicious);
		properties.emplace(L"Other Yara Rules", identifier);
	}
	if(FileSigned) properties.emplace(L"Signed", *FileSigned ? true : false);
	if(Signer) properties.emplace(L"Signer", *Signer);
	return properties;
}

RegistryDetectionData::RegistryDetectionData(
	IN CONST Registry::RegistryKey& key,
	IN CONST std::optional<Registry::RegistryValue>& value = std::nullopt OPTIONAL,
	IN CONST std::optional<AllocationWrapper>& data = std::nullopt OPTIONAL
) : KeyPath{ key.GetName() },
    key{ key },
	value{ value },
	data{ data }{}

ServiceDetectionData::ServiceDetectionData(
	IN CONST std::wstring& ServiceName,
	IN CONST std::optional<std::wstring>& DisplayName OPTIONAL,
	IN CONST std::optional<std::wstring>& Description OPTIONAL
) : ServiceName{ ServiceName },
    DisplayName{ DisplayName },
	Description{ Description }{}

OtherDetectionData::OtherDetectionData(
	IN CONST std::wstring& DetectionType,
	IN CONST std::unordered_map<std::wstring, std::wstring>& DetectionProperties
) : DetectionType{ DetectionType },
    DetectionProperties{ DetectionProperties }{}

