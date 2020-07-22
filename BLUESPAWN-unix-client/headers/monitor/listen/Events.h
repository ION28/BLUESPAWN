#pragma once

#include <atomic>
#include <pthread.h>
#include <optional>
#include <string>
#include <atomic>
#include <linux/ptrace.h>

#include "util/ThreadsafeQueue.h"
#include "util/ThreadsafeMap.h"
#include "monitor/Event.h"

#define WAIT_OBJECT_0 0
#define INFINITE -1

namespace Events{

class EventDetails;

static std::atomic_uint currId = 0;

/**
 * A class capable of describing an event to subscribe to
 * 
 */ 
class EventHandle{
private:
    pthread_cond_t condition;
    pthread_mutex_t mutex;
    unsigned int id;
public:

    EventHandle();

    ~EventHandle();

    void Set();

    int Wait(int timeout, bool * done);

    bool operator==(const EventHandle &other) const;

};

//an implementation of WaitForMultipleObjects to reduce overhead in the eventsListener class
int WaitForMultipleObjects(int nCount, Events::EventHandle * lpHandles, bool bWaitAll, int dwMilliSeconds);

//for compatibility with the WaitForSingleObjects on the hManager event handle
bool WaitForSingleObject(Events::EventHandle * hHandle, int dwMilliseconds);

Events::EventHandle * CreateEvent();

void SetEvent(Events::EventHandle * handle);

void CloseHandle(Events::EventHandle * handle);
//holds dynamic event details
enum class EventType{
    SystemCall,
    FileSystem,
    ProcessSignal
};

class EventDetails{
private:
    EventType type;
    //required
    pid_t pid; //pid that spawned the event

    time_t timestamp; //timestamp of the event
    //system call specific options
    std::optional<long> number;
    std::optional<struct pt_regs> registers;

    //filesystem specific
    std::optional<std::string> path;
    std::optional<mode_t> mode;

    //process specific
    std::optional<pid_t> on; //on fork events, its the child process spawned.  On signal events, its the process that was signaled.
    std::optional<int> signal; //signal only
public:
    EventDetails(pid_t pid, long number, struct pt_regs * registers);

    EventDetails(pid_t pid, std::string path, mode_t mode);

    EventDetails(pid_t pid, pid_t on, int signal);

    bool operator==(const EventDetails& other) const;

    EventType GetType() const;

    pid_t GetPid() const;

    std::optional<long> GetSyscallNumber() const;

    std::optional<struct pt_regs> GetRegisters() const;

    std::optional<std::string> GetPath() const;

    std::optional<mode_t> GetOperation() const;

    std::optional<pid_t> GetChild() const;

    std::optional<int> GetSignal() const;

    time_t GetTimestamp() const;

    ProcessEventAction GetProcessEventType() const;
};

};
