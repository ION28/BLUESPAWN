#pragma once

#include "Call.h"

namespace BLUESPAWN::Agent{

	enum class CallAction {
		Blocked,
		Modified,
		Allowed
	};

	/**
	 * \brief Keeps track of all hooks and calls to hooked functions
	 */
	class HookRegister {

		/// hooks can only be registered via HookRegistration
		friend class HookRegistration;

		/**
		 * \brief Registers a hook to a new function, given its name and library, the function to use as a hook, and a 
		 *		  pointer that will receive a pointer to the old function.
		 * 
		 * \param[in]  mod  The name of the module in which the function can be found
		 * \param[in]  name The name of the function to hook
		 * \param[in]  hook A pointer to the hook to replace the function
		 * \param[out] old  Receives a pointer to the original function
		 * 
		 * \return true if successful; false if an error occured
		 */
		_Success_(return == true)
		bool RegisterHook(_In_ const std::wstring& mod, _In_ const std::string& name, _In_ LPVOID hook,
						  _Out_ LPVOID* old);

	public:

		/**
		 * \brief Requests BLUESPAWN client to make a determination for which action should be taken on a call
		 * 
		 * \details Hooks using this function should note that this will cause the function to take much longer than it
		 *          normally would due to the required interprocess communication.
		 * 
		 * \param[in] call The call for which an action is being requested
		 */
		CallAction GetAction(_In_ const Call& call);

		/**
		 * \brief Records a call to a hooked function and the action taken on the call
		 */
		void RecordCall(_In_ const Call& call, _In_ CallAction action);
	};

	/**
	 * \brief Represents a hook's registration to the hook register. Hook should register themselves by constructing a
	 *        HookRegistration object describing the hook. 
	 */
	class HookRegistration {
	private:

		/// The name of the library containing the function
		std::wstring library;

		/// The name of the function being hooked
		std::string name;
		
		/// A pointer to the hook to replace the function
		LPVOID hook;

		/// A pointer to a value which will receive a pointer to the original function
		LPVOID* old;

	public:

		/**
		 * \brief Constructs a hook registration and registers the hook via RegisterHook
		 * 
		 * \param[in]  mod  The name of the module in which the function can be found
		 * \param[in]  name The name of the function to hook
		 * \param[in]  hook A pointer to the hook to replace the function
		 * \param[out] old  Receives a pointer to the original function
		 */
		HookRegistration(_In_ const std::wstring& mod, _In_ const std::string& name, 
						 _In_ LPVOID hook, _Out_ LPVOID* old);
		~HookRegistration();
	};
}