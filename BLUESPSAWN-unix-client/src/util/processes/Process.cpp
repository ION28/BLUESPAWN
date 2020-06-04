#include "util/processes/Process.h"
namespace Process{
    ProcessInfo::ProcessInfo(pid_t pid){
        this->pid = pid;
        ReadProcExe();
    }

    ProcessInfo::~ProcessInfo(){

    }

    void ProcessInfo::ReadProcExe(){
        char path[PATH_MAX + 1];
        snprintf(path, PATH_MAX + 1, "/proc/%d", pid);
        struct stat statbuf;
        this->error = false;
        if(stat(path, &statbuf) < 0){
            if(errno == ENOENT){
                LOG_ERROR("Process " << std::to_string(this->exists) << "does not exist.");
                this->exists = false;
            }else if(errno == EPERM){
                LOG_ERROR("Unable to read /proc.");
                this->error = true;
            }
        }

        strncat(path, "/exe", PATH_MAX + 1);
        char linkbuf[PATH_MAX + 1];
        if(readlink(path, linkbuf, PATH_MAX + 1) < 0){
            LOG_ERROR("Unable to read " << std::string(path) << ".");
            this->error = true;
        }

        this->processExecutable = std::string(linkbuf);
    }

    pid_t ProcessInfo::GetProcessId(){
        this->pid;
    }

    std::string ProcessInfo::GetProcessExecutable(){
        return this->processExecutable;
    }

    bool ProcessInfo::Exists(){
        return this->exists;
    }

    bool ProcessInfo::Error(){
        return this->error;
    }
}