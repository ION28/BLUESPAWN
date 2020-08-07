#pragma once

#include <functional>
#include <queue>
#include <memory>
#include <vector>
#include <thread>

#include "util/Promise.h"
#include "util/wrappers.hpp"

class ThreadPool {
private:

	/// A queue of tasks to be executed by the threadpool
	std::queue<std::function<void()>> tasks;

	/// A vector of worker threads 
	std::vector<std::thread> threads;

	/// A critical section guarding access to tasks and threads
	CriticalSection hGuard;

	/// A semaphore counting the number of tasks in the queue
	HandleWrapper hSemaphore;

	/// An event object that will be signalled whenever the threadpool has no remaining tasks
	HandleWrapper hEvent;

	/// A boolean indicating whether the threadpool is active. If false, all threads will
	/// terminate when they finish their tasks.
	bool active;

	/// The number of tasks not finished being executed. Access is protected by hGuard
	size_t count;

	/// The threadpool instance
	static ThreadPool instance;

	/// Private constructor
	ThreadPool();

	/// A vector of functions to be called when an exception is raised
	std::vector<std::function<void(const std::exception& e)>> vExceptionHandlers;

	/// The function that each worker thread runs in, for internal use only
	void ThreadFunction();

public:

	~ThreadPool();

	/**
	 * Returns a reference to the threadpool instance
	 */
	static ThreadPool& GetInstance();

	// Delete the move and copy constructors; this is a singleton class
	ThreadPool(const ThreadPool&) = delete;
	ThreadPool(ThreadPool&&) = delete;
	ThreadPool operator=(const ThreadPool&) = delete;
	ThreadPool operator=(ThreadPool&&) = delete;

	/**
	 * Enqueues a task to the threadpool. This task will be executed at some
	 * point in the future by the threadpool.
	 */
	void EnqueueTask(
		IN CONST std::function<void()>& task
	);

	/**
	 * Enqueue a function to the threadpool and return a promise for its return value. The promise will be fufilled if
	 * the function returns a value or invalidated if the function throws an exception. If more complex fufillment or 
	 * invalidation guidelines are required, design an std::function to handle creation of the promise and use 
	 * EnqueueTask instead.
	 *
	 * @param function The function to return a promise for
	 *
	 * @return A promise which will hold the return value of the function
	 */
	template<class T>
	Promise<T> RequestPromise(
		IN CONST std::function<T()>& function
	){
		Promise<T> promise{ false };
		EnqueueTask([promise, function]() mutable {
			try {
				promise.Fufill(function());
			} catch(...){
				promise.Invalidate();
			}
		});
		return promise;
	}

	/**
	 * Adds a function to be called whenever a task raises an exception. This
	 * function call will be enqueued as a separate task to the threadpool rather
	 * than being immediately handled. 
	 *
	 * @param function A function to be called whenever a task raises an exception.
	 *        The exception will be passed as an argument to the function.
	 */
	void AddExceptionHandler(
		IN CONST std::function<void(const std::exception& e)>& function
	);

	/**
	 * Waits for all tasks to be finished before returning.
	 */
	void Wait() const;
};
