#pragma once

#include <vector>
#include <optional>
#include <functional>
#include "reaction/Reaction.h"
#include "hunt/Scope.h"
#include "util/eventlogs/EventSubscription.h"
#include "util/eventlogs/XpathQuery.h"
#include "util/filesystem/FileSystem.h"

enum class EventType {
	EventLog,
	FileSystem
};

class Event {
public:
	EventType type;

	void AddCallback(const std::function<void()>& callback);

	virtual void RunCallbacks() const;

	virtual bool Subscribe() = 0;

	virtual bool operator==(const Event& e) const = 0;

protected:
	Event(EventType type);

	std::vector<std::function<void()>> callbacks;
	Reaction reaction;
	std::optional<Scope> scope;

};

class EventLogEvent : public Event {
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
};