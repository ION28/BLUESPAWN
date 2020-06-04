#include <string>
#include <iostream>
#include <libgen.h>
#include <signal.h>

#include "reaction/SuspendProcess.h"
#include "common/wrappers.hpp"
#include "util/log/Log.h"
#include "util/processes/Process.h"
#include "util/filesystem/FileSystem.h"
#include "common/StringUtils.h"

namespace Reactions{
	//TODO: Suspend any children processes as well.
	std::vector<pid_t> SuspendProcessReaction::GetProcessesWithExe(const std::string& file) const {
		std::vector<pid_t> pids = std::vector<pid_t>();
		FileSystem::Folder procfs = FileSystem::Folder("/proc");
		if(procfs.GetFileExists()){ //procfs should never be empty
			do{
				if(!procfs.GetCurIsFile()){
					std::optional<FileSystem::Folder> proc = procfs.EnterDir();
					if(proc.has_value()){
						FileSystem::Folder procfolder = proc.value();
						if(procfolder.GetFileExists()){
							char path[PATH_MAX + 1];
							strncpy(path, procfolder.GetFilePath().c_str(), PATH_MAX + 1);
							char * base = basename(path);
							if(StringIsNumber(std::string(base))){
								pid_t pid = std::atoi(base);
								Process::ProcessInfo procInfo = Process::ProcessInfo(pid);
								if(procInfo.Error() || !procInfo.Exists()){
									LOG_ERROR("An error occurred while getting info for " << std::to_string(pid) << ".");
								}else{
									if(file == procInfo.GetProcessExecutable()){
										procfolder.Close();
										pids.emplace_back(pid);
									}
								}
							}
						}

						procfolder.Close();
					}
				}
			}while(procfs.MoveToNextFile());
		}else{
			LOG_ERROR("Unable to open /proc - may not have permission");
		}

		procfs.Close();
		return pids;
	}

	void SuspendProcessReaction::SuspendFileIdentified(std::shared_ptr<FILE_DETECTION> detection){
		auto ext = detection->wsFileName.substr(detection->wsFileName.size() - 4);

		if(io.GetUserConfirm(detection->wsFileName + " appears to be a malicious file. Suspend related processes?") == 1){
			std::vector<pid_t> processes = GetProcessesWithExe(detection->wsFilePath);

			for(auto pid : processes){
				if(kill(pid, SIGSTOP) != 0){
					LOG_ERROR("Unable to kill process " << std::to_string(pid) << ".");
				}

				LOG_VERBOSE(2, "Suspended process " << std::to_string(pid) << ".");
			}
		}
	}

	void SuspendProcessReaction::SuspendProcessIdentified(std::shared_ptr<PROCESS_DETECTION> detection){
		//NOTE: we dont check if it exists here
		if(io.GetUserConfirm(detection->wsCmdline + " appears to be infected.  Suspend process?") == 1){
			if(kill(detection->PID, SIGSTOP) != 0){
				LOG_ERROR("Unable to suspend process " << std::to_string(detection->PID) << ".");
			}else{
				LOG_VERBOSE(2, "Suspended process");
			}
		}
	}

	void SuspendProcessReaction::SuspendServiceIdentified(std::shared_ptr<SERVICE_DETECTION> detection){
		if(io.GetUserConfirm("Service " + detection->wsServiceName + " appears to be infected. Suspend process?") == 1){
			if(kill(detection->ServicePID, SIGSTOP) != 0){
				LOG_ERROR("Unable to suspend process " << std::to_string(detection->ServicePID) << ".");
			}else{
				LOG_VERBOSE(2, "Suspended process");
			}
		}
	}

	SuspendProcessReaction::SuspendProcessReaction(const IOBase& io) : io{ io }{
		vFileReactions.emplace_back(std::bind(&SuspendProcessReaction::SuspendFileIdentified, this, std::placeholders::_1));
		vProcessReactions.emplace_back(std::bind(&SuspendProcessReaction::SuspendProcessIdentified, this, std::placeholders::_1));
		vServiceReactions.emplace_back(std::bind(&SuspendProcessReaction::SuspendServiceIdentified, this, std::placeholders::_1));
	}
}