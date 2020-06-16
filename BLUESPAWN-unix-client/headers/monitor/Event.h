#pragma once

#include <vector>
#include <optional>
#include <functional>
#include "reaction/Reaction.h"
#include "hunt/Scope.h"
#include "util/eventlogs/EventSubscription.h"
#include "util/eventlogs/XpathQuery.h"
#include "util/filesystem/FileSystem.h"

#include <linux/ptrace.h>

enum class EventType {
	EventLog,
	FileSystem
};

/**
 * 
 * Kindof thinking for the event structure on linux to do something like below:
 * 
 * An event is sent to listeners on a filesystem.  Listeners can be for specific events.  Once an event is registered, if that
 * event is deteected it is thrown to listeners that are registered for that event
 * 
 * some sort of std::unordered_map that links to std::list for each event.
 * 
 */
class Event {
public:

	void AddCallback(const std::function<void()>& callback);

    void RunCallbacks() const; //callbacks are what should be done when an event occurs?

	virtual bool operator==(const Event& e) const = 0;

protected:
	EventType type;

	time_t timestamp;

    Event(EventType &type);

	std::vector<std::function<void()>> callbacks;

	std::optional<Scope> scope;

};

enum class FileEventAction{
	Read,
	Write,
	Execute
};

class FileEvent : public Event {
protected:
	std::string path;
	FileEventAction action;
	Permissions::User user; //who did it

};

class SystemCallEvent : public Event {
	//so that we can look at certain system calls
	int num;
	struct pt_regs regs;
};

enum class ProcessEventAction{
	Create, //fork
	Signal
};

class ProcessEvent : public Event {
	pid_t ppid;
	pid_t pid;
	ProcessEventAction action;
	std::optional<int> signo; //for signal events
	Permissions::User user;

}

//add any other events i can think of

/*class EventLogEvent : public Event {
public:
	EventLogEvent(const std::string & channel, int eventID, const std::vector<EventLogs::XpathQuery>& queries = {});

	std::function<void(EventLogs::EventLogItem)> eventLogTrigger;

	std::string GetChannel() const;
	int GetEventID() const;
	std::vector<EventLogs::XpathQuery> GetQueries() const;

	virtual bool Subscribe();

	virtual bool operator==(const Event& e) const;

private:
	std::optional<EventSubscription> eventSub;
	std::string channel;
	int eventID;
	std::vector<EventLogs::XpathQuery> queries;
};

class FileEvent : public Event {

	/// Directory to be watched
	FileSystem::Folder directory;

	/// Event that is triggered when the key changes
	GenericWrapper<HANDLE> hEvent;

public:
	FileEvent(const FileSystem::Folder& file);

	const GenericWrapper<HANDLE>& GetEvent() const;

	const FileSystem::Folder& GetFolder() const;

	virtual bool Subscribe();

	virtual bool operator==(const Event& e) const;
	
};*/