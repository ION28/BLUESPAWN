#pragma once

#include <windows.h>

#include <optional>
#include <functional>

#include "util/wrappers.hpp"

// https://stackoverflow.com/questions/6534041/how-to-check-whether-operator-exists
// Used to avoid a requirement for all types used in a promise to have an == operator
// defined.
namespace detail{
	template<typename L, typename R = L>
	struct has_operator_equals_impl {
		template<typename T = L, typename U = R> // template parameters here to enable SFINAE
		static auto test(T&& t, U&& u) -> decltype(t == u, void(), std::true_type{});
		static auto test(...) -> std::false_type{};
		using type = decltype(test(std::declval<L>(), std::declval<R>()));
	};
} // namespace detail

/**
 * Represents a value from an asynchronous function that may be available later.
 */
template<class T>
class Promise {
private:

	/// Indicates whether the promise is guaranteed to be fufilled
	const bool guaranteed;

	/// An event that will be set when the promise is either fufilled or
	/// invalidated
	const HandleWrapper hEvent;

	/// A critical section used to guard access to members of this class
	const CriticalSection hGuard;

	/// A struct containing members meant to be the same across all copies
	/// of the same Promise. These will be held in a shared pointer.
	struct Members {
		/// Holds the value used to fufill the promise, if any
		std::optional<T> value;

		/// A vector of functions to be called when the promise is fufilled
		std::vector<std::function<void(const T&)>> SuccessFunctions;

		/// A vector of functions to be called when the promise is invalidated
		std::vector<std::function<void()>> FailureFunctions;
	};

	/// A shared pointer to members, to be shared across copies of the same 
	/// promise.
	std::shared_ptr<Members> members;


public:

	/**
	 * Instantiates a promise.
	 *
	 * @param guaranteed Indicates whether this promise is guaranteed not to be
	 *        invalidated.
	 */
	Promise(
		IN bool guaranteed = false OPTIONAL
	) : guaranteed{ guaranteed },
		hEvent{ CreateEventW(nullptr, true, false, nullptr) },
		hGuard{}, 
		members{ std::make_shared<Members>() }{}

	/**
	 * Instantiates a promise already fufilled.
	 *
	 * @param guaranteed Indicates whether this promise is guaranteed not to be
	 *        invalidated.
	 */
	Promise(
		IN CONST T& value
	) : guaranteed{ true },
		hEvent{ CreateEventW(nullptr, true, true, nullptr) },
		hGuard{},
		members{ std::make_shared<Members>(value) }{}


	/**
	 * Waits for the promise to be either fufilled or invalidated, and then
	 * returns an optional, holding the value used to fufill it or nullopt
	 * if invalidated.
	 *
	 * @return Returns an optional, holding the value used to fufill it or 
	 * nullopt if invalidated.
	 */
	std::optional<T> GetValue() const {
		auto status{ WaitForSingleObject(hEvent, INFINITE) };
		if(status != WAIT_OBJECT_0){
			throw std::exception("Waiting for value failed");
		}

		return members->value;
	}

	/**
	 * Adds a functioned to be called if the promise is fufilled. If the promise
	 * has already been fufilled, then the provided function will be immediately
	 * called. Note that the provided function will be called by the thread fufilling
	 * the promise if the promise has not yet been fufilled, so it may be preferable
	 * to design the callback to queue a task to a threadpool or start a new thread.
	 *
	 * @param callback The function to call if and when the promise is fufilled.
	 */
	void OnSuccess(
		IN CONST std::function<void(const T&)>& callback
	){
		EnterCriticalSection(hGuard);

		if(!Fufilled()){
			members->SuccessFunctions.emplace_back(callback);
			LeaveCriticalSection(hGuard);
		} else{
			LeaveCriticalSection(hGuard);
			if(value){
				callback(*value);
			}
		}
	}

	/**
	 * Adds a functioned to be called if the promise is invalidated. If the promise 
	 * has already been invalidated, then the provided function will be immediately
	 * called. Note that the provided function will be called by the thread invalidating
	 * the promise if the promise has not yet been invalidating, so it may be preferable
	 * to design the callback to queue a task to a threadpool or start a new thread.
	 *
	 * @param callback The function to call if and when the promise is invalidated.
	 */
	void OnFailure(
		IN CONST std::function<void()>& callback
	){
		EnterCriticalSection(hGuard);

		if(!Fufilled()){
			members->SuccessFunctions.emplace_back(callback);
			LeaveCriticalSection(hGuard);
		} else{
			LeaveCriticalSection(hGuard);
			if(!value){
				callback();
			}
		}
	}

	/**
	 * Attempts to fufill the promise with a value. This will trigger the functions 
	 * registered with OnSuccess if successful. 
	 *
	 * @return True if the promise has been fufilled with the value provided; false
	 *         if the promise had already been fufilled using a different value or if
	 *         the promise has been invalidated.
	 */
	bool Fufill(
		IN CONST T& value
	){
		EnterCriticalSection(hGuard);

		if(!Finished()){
			members->value = value;
			SetEvent(hEvent);
			auto copy{ members->SuccessFunctions };

			LeaveCriticalSection(hGuard);

			for(const auto& func : copy){
				func(value);
			}

			return true;
		} else{
			LeaveCriticalSection(hGuard);
			
			return false;
		}
	}

	/**
	 * Attempts to invalidate the promise, indicating that no value ever be
	 * returned. This will trigger the functions registered with OnFailure if
	 * successful. If the promise has already been fufilled, this will return 
	 * false. Throws an exception if this promise is guaranteed.
	 *
	 * @return True if the promise has been invalidated; false otherwise.
	 */
	bool Invalidate(){
		if(guaranteed){
			throw std::exception("Invalidating a guaranteed promise");
		}

		EnterCriticalSection(hGuard);

		if(!Finished()){
			SetEvent(hEvent);
			auto copy{ members->FailureFunctions };
			LeaveCriticalSection(hGuard);

			for(const auto& func : copy){
				func();
			}

			return true;
		} else{
			LeaveCriticalSection(hGuard);

			return !members->value;
		}
	}

	/**
	 * Indicates whether the promise has been fufilled.
	 *
	 * @return true if this promise has been fufilled; false otherwise.
	 */
	bool Fufilled() const {
		return Finished() && members->value;
	}

	/**
	 * Indicates whether the promise has been invalidated.
	 *
	 * @return true if this promise has been invalidated; false otherwise.
	 */
	bool Invalidated() const {
		return Finished() && !members->value;
	}

	/**
	 * Indicates whether the promise has been either fufilled or invalidated.
	 *
	 * @return true if this promise has been either fufilled invalidated; false otherwise.
	 */
	bool Finished() const {
		return WAIT_TIMEOUT != WaitForSingleObjectEx(hEvent, 0, true);
	}

	/**
	 * Indicates whether this promise is guaranteed to not be invalidated.
	 *
	 * @return True if this promise is guaranteed to not be invalidated; false otherwise.
	 */
	bool IsGuaranteed() const {
		return guaranteed;
	}

	/**
	 * Provides an implicit cast to HANDLE for use in wait functions such as
	 * WaitForSingleObject and similar. This handle will be signalled when the promise
	 * is fufilled or invalidated. Note that this handle should not be set or reset.
	 *
	 * @return A handle to the underlying event for this promise.
	 */
	operator HANDLE() const {
		return hEvent;
	}

	/**
	 * Provides an implicit cast to the expected value type of the promise. Note that
	 * this is an unsafe method and will throw an exception if the promise is invalidated.
	 *
	 * @return The value used to fufill the promise.
	 */
	operator T(){
		GetValue();

		if(!Fufilled()){
			throw std::exception("Attempting to get the value of invalidated promise");
		}

		return *members->value;
	}
};