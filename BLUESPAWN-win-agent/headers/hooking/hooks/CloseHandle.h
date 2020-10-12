#pragma once

#include "hooking/Call.h"
#include "hooking/Hook.h"
#include "hooking/HookRegister.h"
#include "utils/ProcessUtils.h"
#include "utils/Debug.h"
#include "utils/StackWalker.h"

namespace BLUESPAWN::Agent::Hooks{
	class HandleCloseHook : public Hook<decltype(::CloseHandle), HANDLE>{

		/// Parameters for CloseHandle
		enum class Params {
			hObject = 0,
		};

		/// The singleton instance
		static const HandleCloseHook instance;

		/**
		 * \brief Constructs the CloseHandle object and initializes the hook. This is only used by the singleton
		 *        instance.
		 */
		HandleCloseHook();

		/// Delete copy and move constructors
		HandleCloseHook(const HandleCloseHook& other) = delete;
		HandleCloseHook(HandleCloseHook&& other) = delete;
		HandleCloseHook operator=(const HandleCloseHook& other) = delete;
		HandleCloseHook operator=(HandleCloseHook&& other) = delete;

	public:

		/**
		 * \brief Returns a reference to an instance of CloseHandle. This class is a singleton, so this method
		 *        is the way to interact with an instance.
		 *
		 * \return A reference to an instance of CloseHandle.
		 */
		static const HandleCloseHook& GetInstance();

		/**
		 * \brief Hook calls to CloseHandle, allowing threads only to be injected to child processes, but recording
		 *        all calls
		 *
		 * \details See the Windows API documentation for information about the arguments
		 */
		virtual BOOL HookFunc(
			HANDLE                 hObject
		) const override;
	};
}