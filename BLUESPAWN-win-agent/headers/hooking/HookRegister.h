#pragma once

#include "Call.h"

namespace BLUESPAWN::Agent{

	/**
	 * \brief Represents the action taken on a call by a hook
	 */
	enum class CallAction {
		Blocked,
		Modified,
		Allowed
	};

	/**
	 * \brief Used as a delegate to pass calls through the HookFunc method of an instance of the H class. This function
	 *        should only ever be used as a detours hook and never called directly.
	 * 
	 * \param args The arguments being passed to the function. 
	 * 
	 * \return The return value of the function
	 */
	template<class H, class... Args>
	auto WINAPI HookDelegate(Args&&... args){
		return H::GetInstance().HookFunc(args...);
	}

	/**
	 * \brief Keeps track of all hooks and calls to hooked functions
	 */
	class HookRegister {

		/// The singleton instance of the HookRegister
		static HookRegister instance;

		/// Indicates whether the HookRegister has been initialized. When this is false, and hook registered will be
		/// stored rather than applied. When changed to true, all hooks stored will be applied. When changed to false,
		/// all hooks will be removed.
		bool initialized{ false };

		/// A vector containing hooks, stored as pairings between the hook function and pointers to the original 
		/// function.
		std::vector<std::pair<LPVOID, LPVOID*>> hooks{};

	public:

		/**
		 * \brief Registers a hook to a new function, given its name and library, the function to use as a hook, and a
		 *		  pointer that will receive a pointer to the old function.
		 *
		 * \param[in]  hook A pointer to the hook to replace the function
		 * \param[out] old  A pointer to the original function which will receive a new pointer that will call the 
		 *                  original function
		 *
		 * \return true if successful; false if an error occured
		 */
		_Success_(return == true)
		bool RegisterHook(_In_ LPVOID hook, _Inout_ LPVOID* func);

		/**
		 * \brief Initializes the HookRegister, enabling all registered hooks. This should only be called from DllMain
		 *        while dwReason is DLL_PROCESS_ATTACH. This function is not thread safe.
		 */
		void Initialize();

		/**
		 * \brief Deinitializes the HookRegister, disabling all registered hooks. This should only be called from 
		 *        DllMain while dwReason is DLL_PROCESS_DETACH. This function is not thread safe.
		 */
		void Deinitialize();

		/**
		 * \brief Requests that the BLUESPAWN client make a determination for which action should be taken on a call
		 * 
		 * \details Hooks using this function should note that this will cause the function to take much longer than it
		 *          normally would due to the required interprocess communication.
		 * 
		 * \param[in] call The call for which an action is being requested
		 * 
		 * \return The action that BLUESPAWN client indicates be should taken
		 */
		static CallAction GetAction(_In_ const Call& call);

		/**
		 * \brief Records a call to a hooked function and the action taken on the call
		 * 
		 * \param[in] call   The call being recorded
		 * \param[in] action The action taken on the call
		 */
		void RecordCall(_In_ const Call& call, _In_ CallAction action);

		/**
		 * \brief Retrieves a reference to a HookRegister object. 
		 * 
		 * \return A reference to the singleton HookRegister object
		 */
		static HookRegister& GetInstance();
	};
}