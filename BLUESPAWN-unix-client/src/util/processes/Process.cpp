#include "util/processes/Process.h"
/**
 * NOTE: Going to probably need a rewrite for BSD / MacOS compatibility
 */ 
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

        strncat(path, "/exe", PATH_MAX);
        char linkbuf[PATH_MAX + 1];
        if(readlink(path, linkbuf, PATH_MAX + 1) < 0){
            LOG_ERROR("Unable to read " << std::string(path) << ".");
            this->error = true;
        }

        this->processExecutable = std::string(linkbuf);
    }

    pid_t ProcessInfo::GetProcessId(){
        return this->pid;
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

    bool ReadProcessMemory(pid_t pid, void * lpBaseAddress, void * lpBuffer, size_t nSize, size_t * lpNumberOfBytesRead){
        struct iovec local;
        struct iovec remote;
        local.iov_base = lpBuffer;
        local.iov_len = nSize;
        remote.iov_base = lpBaseAddress;
        remote.iov_len = nSize;
        *lpNumberOfBytesRead = process_vm_readv(pid, &local, 1, &remote, 1, 0);
        return *lpNumberOfBytesRead != -1;
    }
    
    bool WriteProcessMemory(pid_t pid, void * lpBaseAddress, void * lpBuffer, size_t nSize, size_t * lpNumberOfBytesWritten){
        struct iovec local;
        struct iovec remote;
        local.iov_base = lpBuffer;
        local.iov_base = lpBuffer;
        local.iov_len = nSize;
        remote.iov_base = lpBaseAddress;
        remote.iov_len = nSize;
        *lpNumberOfBytesWritten = process_vm_writev(pid, &local, 1, &remote, 1, 0);
        return *lpNumberOfBytesWritten != -1;

    }

}