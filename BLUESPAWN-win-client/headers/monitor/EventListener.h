#pragma once

#include <Windows.h>

#include <vector>
#include <map>
#include <thread>

#include "util/wrappers.hpp"

/**
 * An event manager for seemlessly subscribing and unsubscribing to and from events. Since this
 * class can handle all types of events, there is no need for multiple instances. Furthermore,
 * due to the internal structure of the class, it is more efficient the more events there are
 * being subscribed to. For these reasons, EventListener is a singleton class.
 */
class EventListener {
private:

	/**
	 * By default, the maximum number of events that can be waited on by WaitForMultipleObjects is
	 * 64, and it's quite possible that BLUESPAWN will need to be able to wait for more than 64
	 * different events. This class is designed to handle waiting on up to 63 events, triggering
	 * different callbacks for each event triggered.
	 *
	 * This class is meant for internal usage within EventListener
	 */
	class SubEventListener {

		/// Indicates the number of events that can be added before maximum capacity is reached
		DWORD dwSlotsFree;

		/// Stores the event handles being waited on
		std::vector<HANDLE> events;

		/// Maps events to callbacks to be run when the event is triggered
		std::map<HANDLE, std::vector<std::function<void()>>> map;

		/// A critical section guarding accesses to `map`, `events`,  and `dwSlotsFree`
		/// An SRW lock *may* perform better here, but in practice, most accesses will be writes
		CriticalSection hSection;

		/// A manager event, triggered when a new event is to be added to the queue. Used to 
		/// interrupt the current wait so another event can be added.
		/// Always acquire hSection before setting the manager event so that the event listening 
		/// thread can't begin a new wait between when the manager was set and changes are done.
		/// Always set the manager event before modifying `events`, `dwSlotsFree`, or `map`
		HandleWrapper hManager;

		/// A response event triggered whenever the manager trigger is processed. After setting 
		/// hManager, always wait for a response before continuing
		HandleWrapper hManagerResponse;

		/// A handle to the thread waiting on the events
		std::thread hThread;

		/// Keeps track of the number of consecutive wait failures
		DWORD dwFailureCount;

		/// Terminates the thread next time hManager is signaled if true
		bool terminate;

		/// A handler for processing when an event is notified
		void HandleEventNotify(HANDLE hEventNotified);

		/// The listener function run in a separate thread
		void ListenForEvents();

	public:

		/**
		 * Creates the listener, the thread, and the mutex needed to manage the event listening.
		 * The thread will be started in ListenForEvents immediately.
		 */
		SubEventListener();
		~SubEventListener();

		/// Copy constructor is deleted. Since the thread references `this`, it is very difficult to change.
		SubEventListener(const SubEventListener&) = delete;
		SubEventListener operator=(const SubEventListener&) = delete;

		/// Move constructor is deleted. Since the thread references `this`, it is very difficult to change.
		SubEventListener(SubEventListener&&) = delete;
		SubEventListener operator=(SubEventListener&&) = delete;

		/** 
		 * Tries to subscribe to an event. This function will fail if there is no room in this SubEventListener.
		 * If the event has already been subscribed to, the callbacks will be combined with those already present.
		 * Note that if the intent is to add callbacks, it is recommended that TryAddCallbacks be called instead.
		 * This function acquires hSection and releases it upon completion.
		 *
		 * @param hEvent The event being subscribed to or having callbacks added
		 * @param callbacks A vector of functions to be called when the event is triggered
		 *
		 * @return True if the function completed successfully; false if hEvent couldn't be subscribed to.
		 */
		bool TrySubscribe(
			IN const HANDLE& hEvent, 
			IN const std::vector<std::function<void()>>& callbacks
		);

		/**
		 * Checks if this SubEventListener has already subscribed to the given event. If so, this will return
		 * an optional containing the callbacks for the event. Otherwise, std::nullopt will be returned. 
		 * This function acquires hSection and releases it upon completion.
		 *
		 * @param hEvent The event to check the subscription of.
		 *
		 * @return An optional containing the callbacks for the event if present; otherwise std::nullopt
		 */
		std::optional<std::vector<std::function<void()>>> GetSubscription(
			IN const HANDLE& hEvent
		) const;

		/**
		 * Tries to add a callback to an event. This function will fail if there is this SubEventListener isn't
		 * subscribed to hEvent. 
		 * This function acquires hSection and releases it upon completion.
		 *
		 * @param hEvent The event for which the callback will be added
		 * @param callback A function to be called when hEvent is triggered
		 *
		 * @return True if the function completed successfully; false if hEvent wasn't subscribed to
		 */
		bool TryAddCallback(
			IN const HANDLE& hEvent,
			IN const std::function<void()>& callback
		);

		/**
		 * Tries to remove a callback from an event. This function will fail if there is this SubEventListener isn't
		 * subscribed to hEvent. Note that if hEvent's subscription does not contain the callback to be removed, this
		 * function will still return true. If there is a need to determine whether the subscription included the callback,
		 * see GetSubscription.
		 * This function acquires hSection and releases it upon completion.
		 *
		 * @param hEvent The event for which the callback will be removed.
		 * @param callback A function to be removed from the subscription to hEvent.
		 *
		 * @return True if the function is no longer in the subscription to hEvent; false if hEvent wasn't subscribed to
		 */
		bool TryRemoveCallback(
			IN const HANDLE& hEvent,
			IN const std::function<void()>& callback
		);

		/**
		 * Tries to remove the subscription for an event. This function will fail if this SubEventListener isn't
		 * subscribed to hEvent.
		 *
		 * @param hEvent The event whose subscription will be removed.
		 *
		 * @return True if the function completed successfully; false if the function failed
		 */
		bool TryUnsubscribe(
			IN const HANDLE& hEvent
		);
	};

	/// A vector for internal use containing the SubEventListeners.
	std::vector<std::unique_ptr<SubEventListener>> subeventlisteners;

	/// A critical section protecting access to subeventlisteners
	CriticalSection hSection;

	static EventListener instance;

	/// Creates an event listener
	EventListener();

public:

	/**
	 * Returns a reference to an EventListener instance. Since EventListener is a singleton class, this is
	 * the method used to obtain an instance.
	 *
	 * @return A reference to an EventListener instance.
	 */
	static EventListener& GetInstance();

	/**
	 * Tries to subscribe to an event. This function will fail if there is no room in this SubEventListener.
	 * If the event has already been subscribed to, the callbacks will be combined with those already present.
	 * Note that if the intent is to add callbacks, it is recommended that TryAddCallbacks be called instead.
	 * This function acquires hSection and releases it upon completion.Callbacks are handled by the thread that 
	 * manages waiting, so any callback function that requires significant calculation should create a new thread
	 * or signal some other thread to carry out the task.
	 *
	 * @param hEvent The event being subscribed to or having callbacks added
	 * @param callbacks A vector of functions to be called when the event is triggered
	 *
	 * @return True if the function completed successfully; false if hEvent couldn't be subscribed to.
	 */
	bool Subscribe(
		const HANDLE& hEvent,
		const std::vector<std::function<void()>>& callbacks
	);

	/**
	 * Checks if this EventListener has already subscribed to the given event. If so, this will return
	 * an optional containing the callbacks for the event. Otherwise, std::nullopt will be returned.
	 * This function acquires hSection and releases it upon completion.
	 *
	 * @param hEvent The event to check the subscription of.
	 *
	 * @return An optional containing the callbacks for the event if present; otherwise std::nullopt
	 */
	std::optional<std::vector<std::function<void()>>> GetSubscription(
		IN const HANDLE& hEvent
	) const;

	/**
	 * Tries to add a callback to an event. This function will fail if this EventListener is not
	 * subscribed to hEvent. Callbacks are handled by the thread that manages waiting, so any callback 
	 * function that requires significant calculation should create a new thread or signal some other 
	 * thread to carry out the task.
	 * This function acquires hSection and releases it upon completion.
	 *
	 * @param hEvent The event for which the callback will be added
	 * @param callback A function to be called when hEvent is triggered
	 *
	 * @return True if the function completed successfully; false if hEvent wasn't subscribed to
	 */
	bool AddCallback(
		IN const HANDLE& hEvent,
		IN const std::function<void()>& callback
	);

	/**
	 * Tries to remove a callback from an event. This function will fail if there is this EventListener isn't
	 * subscribed to hEvent. Note that if hEvent's subscription does not contain the callback to be removed, this
	 * function will still return true. If there is a need to determine whether the subscription included the 
	 * callback, see GetSubscription. Note that only the callback function is checked; bound arguments are ignored,
	 * which may result in undesired deletion of certain callbacks.
	 * This function acquires hSection and releases it upon completion.
	 *
	 * @param hEvent The event for which the callback will be removed.
	 * @param callback A function to be removed from the subscription to hEvent.
	 *
	 * @return True if the function is no longer in the subscription to hEvent; false if hEvent wasn't subscribed to
	 */
	bool RemoveCallback(
		IN const HANDLE& hEvent,
		IN const std::function<void()>& callback
	);

	/**
	 * Tries to remove the subscription for an event. This function will fail if this SubEventListener isn't
	 * subscribed to hEvent.
	 *
	 * @param hEvent The event whose subscription will be removed.
	 *
	 * @return True if the function completed successfully; false if the function failed
	 */
	bool Unsubscribe(
		IN const HANDLE& hEvent
	);
};