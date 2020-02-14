#pragma once

#include <vector>
#include <optional>
#include <functional>
#include "hunt/reaction/Reaction.h"
#include "hunt/Scope.h"
#include "util/eventlogs/EventSubscription.h"
#include "util/configurations/Registry.h"
#include "util/configurations/RegistryValue.h"

enum class EventType {
	EventLog,
	Registry
};

class Event {
public:
	EventType type;

	void AddCallback(const std::function<void()>& callback);

	void RunCallbacks() const;

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
	EventLogEvent(const std::wstring& channel, int eventID);

	std::function<void(EventLogs::EventLogItem)> eventLogTrigger;

	std::wstring GetChannel() const;
	int GetEventID() const;

	virtual bool Subscribe();

	virtual bool operator==(const Event& e) const;

private:
	std::optional<EventSubscription> eventSub;
	std::wstring channel;
	int eventID;
};

struct RegistryEventThreadArgs;

class RegistryEvent : public Event {
	HandleWrapper hEvent;
	Registry::RegistryKey key;
	bool WatchSubkeys;

	static HandleWrapper hMutex;
	static std::optional<HandleWrapper> hListener;
	static HandleWrapper hSubscribed;
	static std::optional<RegistryEvent> subscribe;
	static void RegistryEventThreadFunction(RegistryEventThreadArgs* WaitObjects);
	static void DispatchRegistryThread();

public:
	RegistryEvent(const Registry::RegistryKey& key, bool WatchSubkeys = false);

	const HandleWrapper& GetEvent() const;

	virtual bool Subscribe();

	virtual bool operator==(const Event& e) const;
};

struct RegistryEventThreadArgs {
	std::optional<HandleWrapper> WaitObjects[MAXIMUM_WAIT_OBJECTS];
	std::optional<RegistryEvent> Events[MAXIMUM_WAIT_OBJECTS - 1];
};