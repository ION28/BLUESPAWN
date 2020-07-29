#pragma once
#include <string>
#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include "util/log/Log.h"

namespace Process{
    /**
     * Represents a running process
     * Basically a utility class to read things off /proc
     * 
     * NOTE: some methods of hiding processes include manipulating /proc so 
     * verification of /proc MUST be done first.
     * 
     * Essentially a mini version of the ps utility
     * 
     * TODO: Make this grab more things about processes from /proc
     */ 

    class ProcessInfo{
    private:
        pid_t pid;
        std::string processExecutable;
        bool exists;
        bool error;

        void ReadProcExe();

    public:

        ProcessInfo(pid_t pid);

        ~ProcessInfo();

        pid_t GetProcessId();

        std::string GetProcessExecutable();

        bool Exists();

        bool Error();

    };

    bool ReadProcessMemory(pid_t pid, void * lpBaseAddress, void * lpBuffer, size_t nSize, size_t * lpNumberOfBytesRead);

    bool WriteProcessMemory(pid_t pid, void * lpBaseAddress, void * lpBuffer, size_t nSize, size_t * lpNumberOfBytesWritten);
}
