#pragma once

#include <functional>
#include <optional>
#include <vector>

#include "util/configurations/Registry.h"
#include "util/configurations/RegistryValue.h"
#include "util/eventlogs/EventSubscription.h"
#include "util/eventlogs/XpathQuery.h"
#include "util/filesystem/FileSystem.h"

#include "hunt/Scope.h"

enum class EventType { EventLog, Registry, FileSystem };

class Event {
    public:
    EventType type;

    void AddCallback(const std::function<void(IN CONST Scope&)>& callback, IN CONST Scope& scope = {} OPTIONAL);

    virtual void RunCallbacks() const;

    virtual bool Subscribe() = 0;

    virtual bool operator==(const Event& e) const = 0;

    protected:
    Event(EventType type);

    std::vector<std::pair<std::function<void(IN CONST Scope&)>, Scope>> callbacks;
};

class EventLogEvent : public Event {
public:

    /**
     * Creates a new event triggered by an xml
     */
    EventLogEvent(
        IN CONST std::wstring& channel, 
        IN int eventID,
        IN CONST std::vector<EventLogs::XpathQuery>& queries = {} OPTIONAL
    );

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

class RegistryEvent : public Event {
    // Event that is triggered when the key changes
    HandleWrapper hEvent;

    // True if this event watches subkeys. Note that this will be unable to determine
    // which value (or subkey) was changed.
    bool WatchSubkeys;

    // The registry key being watched
    Registry::RegistryKey key;

    public:
    RegistryEvent(const Registry::RegistryKey& key, bool WatchSubkeys = false);

    const HandleWrapper& GetEvent() const;

    const Registry::RegistryKey& GetKey() const;

    virtual bool Subscribe();

    virtual bool operator==(const Event& e) const;
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

/// Template specialization defining how unique_ptrs to Events should be hashed
template<>
class std::hash<std::unique_ptr<Event>> {
    size_t operator()(IN CONST std::unique_ptr<Event>& evt) const;
};

/// Template specialization defining how unique_ptrs to Events should be compared
template<>
class std::equal_to<std::unique_ptr<Event>> {
    bool operator()(IN CONST std::unique_ptr<Event>& left, IN CONST std::unique_ptr<Event>& right) const;
};

namespace Registry {

    /**
	 * Creates a vector of events to be triggered when any value under a specified registry key path changes,
	 * automatically mirrored across users if WatchUsers is true and mirrored to WoW64 if WatchWow64 is true. The 
	 * events generated will also trigger when any subkey is changed if WatchSubkeys is set to true.
	 *
	 * @param dest The vector to which events created by this function will be added
     * @param scope The scope for events that are added
	 * @param hkHive The hive under which the path will be searched. If WatchUsers is true, this will be also be 
	 *        substituted by each user's hive. In most cases, hkHive should be HKEY_LOCAL_MACHINE.
	 * @param path The path of the key under the hive.
	 * @param WatchWow64 Indicates whether events should be generated for Wow64 versions of keys, if present
	 * @param WatchUsers Indicates whether events should be generated for the key at the path under each user's hive,
	 *        if present
	 * @param WatchSubkeys Indicates whether all events generated should be triggered when any subkey is modified
	 */
    void GetRegistryEvents(OUT std::vector<std::pair<std::unique_ptr<Event>, Scope>>& dest,
                           IN CONST Scope& scope,
                           IN HKEY hkHive,
                           IN CONST std::wstring& path,
                           IN bool WatchWow64 = true OPTIONAL,
                           IN bool WatchUsers = true OPTIONAL,
                           IN bool WatchSubkeys = false OPTIONAL);
}   // namespace Registry
