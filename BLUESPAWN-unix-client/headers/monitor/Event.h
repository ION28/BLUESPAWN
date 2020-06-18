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
	FileSystem,
	SystemCall
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

//Add watchers for this to actually do the watching for the event - make this sorta like windows
class Event {
public:
	virtual bool operator==(const Event& e) const = 0; //note: == isnt going to be an exact equal

	void AddCallback(const std::function<void()>& callback);

	virtual void RunCallbacks() const;
	
	virtual bool Subscribe() = 0;

	std::optional<Scope> GetScope() const;

	EventType GetType() const;

protected:
    Event(EventType type);
private:
	EventType type;
	std::optional<Scope> scope;



};

enum class FileEventAction{
	Read,
	Write,
	Execute,
	All
};

class FileEvent : public Event {
private:
	std::string path;
	FileEventAction action;
	bool watchSubdirs; //if its a directory, watch anything in the subdirectories as well
public:
    FileEvent(const std::string& path, FileEventAction action, bool watchSubdirs = false);

	std::string GetPath() const;

	bool IsWatchingSubdirs() const;

	FileEventAction GetAction() const;

	virtual bool Subscribe();

	virtual bool operator==(const Event& e) const;

};

class SystemCallEvent : public Event {
	//so that we can look at certain system calls
private:
	int num;
public:
    SystemCallEvent(int num);

	int GetNum() const;

	virtual bool Subscribe();

	virtual bool operator==(const Event& e) const;


};

enum class ProcessEventAction{
	Create, //fork
	Signal
};

class ProcessEvent : public Event {
private:
	ProcessEventAction action; //the action
	std::optional<int> signo; //for signal events
public:
    ProcessEvent(ProcessEventAction action, std::optional<int> signo = std::nullopt);

	ProcessEventAction GetAction() const;

	std::optional<int> GetSignalNumber() const;

	virtual bool Subscribe();

	virtual bool operator==(const Event& e) const;
};