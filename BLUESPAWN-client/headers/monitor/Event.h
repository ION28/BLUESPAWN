#pragma once

#include <vector>
#include <optional>
#include <functional>
#include "hunt/reaction/Reaction.h"
#include "hunt/Scope.h"
#include "util/eventlogs/EventSubscription.h"
#include "util/configurations/Registry.h"
#include "util/configurations/RegistryValue.h"
#include "util/eventlogs/XpathQuery.h"

enum class EventType {
	EventLog,
	Registry
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
	EventLogEvent(const std::wstring & channel, int eventID, const std::vector<EventLogs::XpathQuery>& queries = {});

	std::function<void(EventLogs::EventLogItem)> eventLogTrigger;

	std::wstring GetChannel() const;
	int GetEventID() const;
	std::vector<EventLogs::XpathQuery> GetQueries() const;

	virtual bool Subscribe();

	virtual bool operator==(const Event& e) const;

private:
	std::optional<EventSubscription> eventSub;
	std::wstring channel;
	int eventID;
	std::vector<EventLogs::XpathQuery> queries;
};

struct RegistryEventThreadArgs;

class RegistryEvent : public Event {
	HandleWrapper hEvent;
	bool WatchSubkeys;

	static HandleWrapper hMutex;
	static std::optional<HandleWrapper> hListener;
	static HandleWrapper hSubscribed;
	static std::optional<RegistryEvent> subscribe;
	static void RegistryEventThreadFunction(RegistryEventThreadArgs* WaitObjects);
	static void DispatchRegistryThread();

public:
	Registry::RegistryKey key;

	RegistryEvent(const Registry::RegistryKey& key, bool WatchSubkeys = false);

	const HandleWrapper& GetEvent() const;

	virtual bool Subscribe();

	virtual bool operator==(const Event& e) const;
};

struct RegistryEventThreadArgs {
	HandleWrapper Notify;
	std::optional<RegistryEvent>* Events;
};

namespace Registry {
	std::vector<std::shared_ptr<Event>> GetRegistryEvents(HKEY hkHive, const std::wstring& path, bool WatchWow64 = true, bool WatchUsers = true, bool WatchSubkeys = false);
}