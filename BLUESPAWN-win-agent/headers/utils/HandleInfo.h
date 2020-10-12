#pragma once

#include <Windows.h>

#include <string>
#include <unordered_map>

namespace BLUESPAWN::Agent{

	/// Refers to the various types of HANDLEs
	enum class HandleType{
		Process,
		Thread,
		File,
		Pipe,
		Synchronization, // Refers to a synchronization object such as an event, mutex, or semaphore
		RegistryKey,
		ETW,
		Directory,
		Section,
		ALPCPort,
		SymbolicLink,
		Token,
		Job,
		Invalid,
		Other
	};

	namespace Util{

		/// Performing queries on handles is a costly procedure, so the results are stored in this cache
		extern std::unordered_map<HANDLE, std::pair<HandleType, std::wstring>> handleInfos;

		/**
		 * \brief Removes the provided handle from the handle cache, requiring the next request involving the handle
		 *        to perform all necessary (costly) queries.
		 * 
		 * \details This is intended to be used primarily with the NtClose hook, though other code wishing to ensure 
		 *          that the result from GetHandleType accurately reflects the current state of the system may wish to
		 *          flush the handle from the cache
		 * 
		 * \param[in] hHandle The handle to be flushed from the cache
		 */
		void FlushHandleCache(_In_ HANDLE hHandle);

		/**
		 * \brief Removes all handle from the handle cache, requiring the next request involving any handle to perform 
		 *        all necessary (costly) queries.
		 */
		void FlushHandleCache();

		/**
		 * \brief Attempts to determine the type of object referenced by a handle. 
		 * 
		 * \details Note that some handles cause hangs when they are queried, so it's possible for this function
		 *          to take up to 100 ms to return, which in some cases may be unacceptable latency. This occurs
		 *          primarily when the handle refers to a pipe. In the event that the handle is closed or the handle
		 *          could not be queried for some other reason, this will return HandleType::Invalid.
		 * 
		 * \param[in] hHandle The handle to query
		 * 
		 * \return The type of object referenced by the given handle.
		 */
		HandleType GetHandleType(_In_ HANDLE hHandle);

		/**
		 * \brief Retrieves the name of the object referenced by a handle.
		 * 
		 * \details Note that some handles cause hangs when they are queried, so it's possible for this function
		 *          to take up to 100 ms to return, which in some cases may be unacceptable latency. This occurs
		 *          primarily when the handle refers to a pipe. In the event that the handle is closed, the handle
		 *          could not be queried, or the handle had no name, this will return an empty string.
		 * 
		 * \param[in] The name of the object referenced by the given handle
		 */
		std::wstring GetHandleName(_In_ HANDLE hHandle);
	}
};