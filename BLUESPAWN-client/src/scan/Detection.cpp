#include "scan/Detections.h"

#include "util/processes/ProcessUtils.h"

#include "common/StringUtils.h"
#include "common/Utils.h"

#include <sstream>

size_t ComputeHash(IN CONST std::unordered_map<std::wstring, std::wstring>& map){
	size_t hash{ 0 };

	std::hash<std::wstring> hasher{};
	for(auto& pair : map){
		auto first{ hasher(pair.first) };
		auto second{ hasher(pair.second) };
		hash = ((hash << 35) | (hash >> 29)) ^ ((first >> 32) | ((first << 32) >> 32)) ^
			((second << 32) | ((second >> 32) << 32));
	}

	return hash;
}

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
	IN CONST std::optional<std::wstring>& ImageName OPTIONAL,
	IN CONST std::optional<std::wstring>& ProcessPath OPTIONAL,
	IN CONST std::optional<std::wstring>& ProcessCommand OPTIONAL,
	IN std::unique_ptr<ProcessDetectionData>&& ParentProcess OPTIONAL
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
	IN CONST std::optional<std::wstring>& ImageName OPTIONAL,
	IN CONST std::optional<std::wstring>& ProcessPath OPTIONAL,
	IN CONST std::optional<std::wstring>& ProcessCommand OPTIONAL,
	IN std::unique_ptr<ProcessDetectionData>&& ParentProcess OPTIONAL
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

ProcessDetectionData::ProcessDetectionData(IN ProcessDetectionType type, IN DWORD PID,
	IN CONST std::optional<DWORD>& TID, IN CONST std::optional<HandleWrapper>& ProcessHandle,
	IN CONST std::wstring& ProcessName, IN CONST std::optional<std::wstring>& ProcessPath,
	IN CONST std::optional<std::wstring>& ProcessCommand, IN std::unique_ptr<ProcessDetectionData>&& ParentProcess,
	IN CONST std::optional<PVOID64>& BaseAddress, IN CONST std::optional<DWORD>& MemorySize,
	IN CONST std::optional<std::wstring>& ImageName) :
	type{ type },
	PID{ PID },
	TID{ TID },
	ProcessHandle{ ProcessHandle },
	ProcessName{ ProcessName },
	ProcessPath{ ProcessPath },
	ProcessCommand{ ProcessCommand },
	ParentProcess{ std::move(ParentProcess) },
	BaseAddress{ BaseAddress },
	MemorySize{ MemorySize },
	ImageName{ ImageName }{
	auto tied{ std::tie(type, PID, TID, ProcessHandle, ProcessName, ProcessPath, ProcessCommand, ParentProcess, 
						BaseAddress, MemorySize, ImageName) };

	serialization = std::unordered_map<std::wstring, std::wstring>{
		{ L"Type", type == ProcessDetectionType::MaliciousImage ? L"Image" :
				   type == ProcessDetectionType::MaliciousMemory ? L"Memory" : L"Process"},
		{ L"Name", ProcessName },
		{ L"PID", std::to_wstring(PID) }
	};
	if(TID) serialization.emplace(L"TID", std::to_wstring(*TID));
	if(ProcessPath) serialization.emplace(L"Process Path", *ProcessPath);
	if(ProcessCommand) serialization.emplace(L"Process Command", *ProcessCommand);
	if(ParentProcess) serialization.emplace(L"Parent PID", std::to_wstring(ParentProcess->PID));
	if(BaseAddress){
		std::wstringstream wss{};
		wss << std::hex << *BaseAddress;
		serialization.emplace(L"Base Address", wss.str());
	}
	if(MemorySize) serialization.emplace(L"Memory Size", std::to_wstring(*MemorySize));
	if(ImageName) serialization.emplace(L"Image Name", *ImageName);

	hash = ComputeHash(serialization);
}

const std::unordered_map<std::wstring, std::wstring>& ProcessDetectionData::Serialize() CONST {
	return serialization;
}

size_t ProcessDetectionData::Hash() CONST {
	return hash;
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

	serialization = std::unordered_map<std::wstring, std::wstring>{
		{ L"Path", FilePath },
		{ L"Name", FileName },
		{ L"Exists", FileFound ? L"true" : L"false" },
	};
	if(FileExtension) serialization.emplace(L"Extension", *FileExtension);
	if(FileType) serialization.emplace(L"File Type", *FileType);
	if(Executor) serialization.emplace(L"File Executor", *Executor);
	if(HashInfo.MD5) serialization.emplace(L"MD5 Hash", *HashInfo.MD5);
	if(HashInfo.SHA1) serialization.emplace(L"SHA1 Hash", *HashInfo.SHA1);
	if(HashInfo.SHA256) serialization.emplace(L"SHA256 Hash", *HashInfo.SHA256);
	if(TimestampInfo.LastOpened) serialization.emplace(L"Last Opened", FormatWindowsTime(*TimestampInfo.LastOpened));
	if(TimestampInfo.FileCreated) serialization.emplace(L"Date Created", FormatWindowsTime(*TimestampInfo.FileCreated));
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
		serialization.emplace(L"Malicious Yara Rules", malicious);
		serialization.emplace(L"Other Yara Rules", identifier);
	}
	if(FileSigned) serialization.emplace(L"Signed", *FileSigned ? L"true" : L"false");
	if(Signer) serialization.emplace(L"Signer", *Signer);

	hash = ComputeHash(serialization);
}

FileDetectionData::FileDetectionData(
	IN CONST std::wstring& path
) : FileDetectionData(FileSystem::File{ path }, std::nullopt){}

const std::unordered_map<std::wstring, std::wstring>& FileDetectionData::Serialize() CONST {
	return serialization;
}

size_t FileDetectionData::Hash() CONST {
	return hash;
}

RegistryDetectionData::RegistryDetectionData(
	IN CONST Registry::RegistryKey& key,
	IN CONST std::optional<Registry::RegistryValue>& value OPTIONAL,
	IN RegistryDetectionType type OPTIONAL,
	IN CONST std::optional<AllocationWrapper>& data OPTIONAL
) : KeyPath{ key.GetName() },
    key{ key },
	value{ value },
	type{ type },
	data{ data }{

	serialization = std::unordered_map<std::wstring, std::wstring>{
		{ L"Key Path", key.GetName() },
	    { L"Registry Entry Type", type == RegistryDetectionType::CommandReference ? L"Command" :
		                          type == RegistryDetectionType::Configuration ? L"Configuration" :
		                          type == RegistryDetectionType::FileReference ? L"File" :
		                          type == RegistryDetectionType::FolderReference ? L"Folder" : 
		                          type == RegistryDetectionType::PipeReference ? L"Pipe" : 
		                          type == RegistryDetectionType::ShareReference ? L"Share" : 
		                          type == RegistryDetectionType::UserReference ? L"User" : L"Unknown" }
	};
	if(value){
		serialization.emplace(L"Key Value Name", value->wValueName);
		serialization.emplace(L"Key Value Data", value->ToString());
	}

	hash = ComputeHash(serialization);
}

const std::unordered_map<std::wstring, std::wstring>& RegistryDetectionData::Serialize() CONST{
	return serialization;
}

size_t RegistryDetectionData::Hash() CONST{
	return hash;
}

ServiceDetectionData::ServiceDetectionData(
	IN CONST std::wstring& ServiceName,
	IN CONST std::optional<std::wstring>& DisplayName OPTIONAL,
	IN CONST std::optional<std::wstring>& Description OPTIONAL
) : ServiceName{ ServiceName },
    DisplayName{ DisplayName },
	Description{ Description }{

	serialization = std::unordered_map<std::wstring, std::wstring>{
		{ L"Service Name", ServiceName },
	};
	if(DisplayName){ serialization.emplace(L"Display Name", *DisplayName); }
	if(Description){ serialization.emplace(L"Description", *Description); }

	hash = ComputeHash(serialization);
}

const std::unordered_map<std::wstring, std::wstring>& ServiceDetectionData::Serialize() CONST{
	return serialization;
}

size_t ServiceDetectionData::Hash() CONST{
	return hash;
}

OtherDetectionData::OtherDetectionData(
	IN CONST std::wstring& DetectionType,
	IN CONST std::unordered_map<std::wstring, std::wstring>& DetectionProperties
) : DetectionType{ DetectionType },
    DetectionProperties{ DetectionProperties },
    serialization(DetectionProperties.begin(), DetectionProperties.end()){

	serialization.emplace(L"Detection Type", DetectionType); 
	hash = ComputeHash(serialization);
}

const std::unordered_map<std::wstring, std::wstring>& OtherDetectionData::Serialize() CONST{
	return serialization;
}

size_t OtherDetectionData::Hash() CONST{
	return hash;
}

DetectionContext::DetectionContext(IN CONST std::optional<std::wstring>& hunt OPTIONAL,
								   IN CONST std::optional<FILETIME>& FirstEvidenceTime OPTIONAL,
								   IN CONST std::optional<std::wstring>& note OPTIONAL) :
	FirstEvidenceTime{ FirstEvidenceTime },
	note{ note }{
	if(hunt) hunts.emplace(*hunt);

	FILETIME time{};
	GetSystemTimeAsFileTime(&time);
	DetectionCreatedTime = time;
}

size_t std::hash<Detection>::operator()(IN CONST Detection& detection) CONST {
	return std::visit(detection.hasher, detection.data);
}

size_t std::hash<std::reference_wrapper<Detection>>::operator()(
	IN CONST std::reference_wrapper<Detection>& detection) CONST {

	return std::visit(detection.get().hasher, detection.get().data);
}