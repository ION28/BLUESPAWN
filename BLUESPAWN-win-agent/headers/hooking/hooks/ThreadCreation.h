#pragma once

#include "hooking/Call.h"
#include "hooking/Hook.h"
#include "hooking/HookRegister.h"
#include "utils/ProcessUtils.h"
#include "utils/Debug.h"
#include "utils/StackWalker.h"

namespace BLUESPAWN::Agent::Hooks {
	class CreateRemoteThread : public Hook<decltype(::CreateRemoteThread), 
		HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD>{

		/// Parameters for CreateRemoteThread
		enum class Params {
			hProcess = 0,
			lpThreadAttributes = 1,
			dwStackSize = 2,
			lpStartAddress = 3,
			lpParameter = 4,
			dwCreationFlags = 5,
			lpThreadId = 6
		};

		/// The singleton instance
		static const CreateRemoteThread instance;

		/**
		 * \brief Constructs the CreateRemoteThread object and initializes the hook. This is only used by the singleton
		 *        instance.
		 */
		CreateRemoteThread();

		/// Delete copy and move constructors
		CreateRemoteThread(const CreateRemoteThread& other) = delete;
		CreateRemoteThread(CreateRemoteThread&& other) = delete;
		CreateRemoteThread operator=(const CreateRemoteThread& other) = delete;
		CreateRemoteThread operator=(CreateRemoteThread&& other) = delete;

	public:

		/**
		 * \brief Returns a reference to an instance of CreateRemoteThread. This class is a singleton, so this method
		 *        is the way to interact with an instance.
		 * 
		 * \return A reference to an instance of CreateRemoteThread.
		 */
		static const CreateRemoteThread& GetInstance();

		/**
		 * \brief Hook calls to CreateRemoteThread, allowing threads only to be injected to child processes, but recording
		 *        all calls
		 *
		 * \details See the Windows API documentation for information about the arguments
		 */
		virtual HANDLE HookFunc(
			HANDLE                 hProcess,
			LPSECURITY_ATTRIBUTES  lpThreadAttributes,
			SIZE_T                 dwStackSize,
			LPTHREAD_START_ROUTINE lpStartAddress,
			LPVOID                 lpParameter,
			DWORD                  dwCreationFlags,
			LPDWORD                lpThreadId
		) const override;
	};
}