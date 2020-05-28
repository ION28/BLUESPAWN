#include "reaction/Detections.h"

#include "util/processes/ProcessUtils.h"

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
	IN CONST std::optional<PVOID64>& BaseAddress = std::nullopt OPTIONAL,
	IN CONST std::optional<DWORD>& MemorySize = std::nullopt OPTIONAL,
	IN CONST std::optional<std::wstring>& ProcessPath = std::nullopt OPTIONAL,
	IN CONST std::optional<std::wstring>& ProcessCommand = std::nullopt OPTIONAL,
	IN std::unique_ptr<ProcessDetectionData>&& ParentProcess = nullptr OPTIONAL
){
	auto addr{ BaseAddress ? *BaseAddress : GetModuleAddress(ProcessHandle, ImageName) };

	return ProcessDetectionData{
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