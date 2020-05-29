#pragma once

#include <functional>
#include <queue>
#include <memory>
#include <vector>
#include <thread>

#include "common/Promise.h"
#include "common/wrappers.hpp"

class ThreadPool {
private:

	/// A queue of tasks to be executed by the threadpool
	std::queue<std::function<void()>> tasks;

	/// A vector of threads 
	std::vector<std::thread> threads;

	/// A critical section guarding access to tasks and threads
	CriticalSection hGuard;

	/// A semaphore counting the number of tasks in the queue
	HandleWrapper hSemaphore;

	/// The threadpool instance
	static ThreadPool instance;

	/// Private constructor
	ThreadPool();

	/// The function that each thread runs in, for internal use only
	void ThreadFunction();

public:

	/**
	 * Returns a reference to the threadpool instance
	 */
	ThreadPool& GetInstance();

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
	 * Enqueue a function to the threadpool and return a promise for its
	 * return value. The promise will be fufilled if the function returns
	 * a value or invalidated if the function throws an exception. If more
	 * complex fufillment or invalidation guidelines are required, design
	 * an std::function to handle creation of the promise and use EnqueueTask
	 * instead.
	 */
	template<class T>
	std::unique_ptr<Promise<T>> RequestPromise(
		IN CONST std::function<T()>& function
	){
		auto promise{ std::make_unique<Promise<T>>(false) };
		EnqueueTask([promise](){
			try {
				promise->Fufill(function());
			} catch(...){
				promise->Invalidate();
			}
		});
		return std::move(promise);
	}
};